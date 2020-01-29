use crate::buffer::Buffer;
use crate::errors::Error;
use crate::sodium;
use crate::sodium::secretstream;
use byteorder::{BigEndian, ByteOrder};
use std::borrow::BorrowMut;
use std::cmp::min;
use std::io;
use std::io::prelude::*;
use std::mem::size_of;
use std::path::Path;

pub struct StreamWriter<W: Write> {
    writer: Option<W>,
    stream: secretstream::SecretStream,
}

pub struct StreamReader<R: Read> {
    reader: Option<R>,
    stream: secretstream::SecretStream,
    buf: Buffer,
}

impl<W: Write> StreamWriter<W> {
    pub fn new(mut writer: W, key: &[u8]) -> Result<Self, Error> {
        let key = secretstream::generate_key();
        let pusher = secretstream::SecretStream::new_push(&key)?;
        writer.write_all(pusher.get_header().as_slice())?;
        Ok(Self {
            writer: Some(writer),
            stream: pusher,
        })
    }

    pub fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut buf = vec![0u8; size_of::<u64>()];
        BigEndian::write_u64(
            &mut buf,
            (data.len() + secretstream::additional_bytes_per_message()) as u64,
        );
        let l = self.stream.push(&buf, None, None)?;
        let c = self.stream.push(data, None, None)?;
        self.writer.as_mut().unwrap().write_all(l.as_slice())?;
        self.writer.as_mut().unwrap().write_all(c.as_slice())?;
        Ok(())
    }
}

impl<W: Write> Write for StreamWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        let size = min(buf.len(), 1024 * 1024);
        self.write_chunk(&buf[0..size])
            .and_then(|_| Ok(size))
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Error writing ciphertext block: {}", err),
                )
            })
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.writer.as_mut().unwrap().flush()
    }
}

impl<R: Read> StreamReader<R> {
    pub fn new(mut reader: R, key: &[u8]) -> Result<Self, io::Error> {
        let mut header = vec![0u8; secretstream::header_bytes()];
        reader.read_exact(&mut header)?;
        let puller =
            secretstream::SecretStream::new_pull(header.as_slice(), key).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Error opening secret stream: {}", err),
                )
            })?;
        Ok(Self {
            reader: Some(reader),
            stream: puller,
            buf: Buffer::with_capacity(4 * 1024 * 1024),
        })
    }
    pub fn read_chunk(&mut self) -> io::Result<Vec<u8>> {
        let mut encrypted_header =
            vec![0u8; size_of::<u64>() + secretstream::additional_bytes_per_message()];
        self.reader
            .as_mut()
            .unwrap()
            .read_exact(&mut encrypted_header)?;
        let header = self
            .stream
            .pull(encrypted_header.as_slice(), None)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Error decoding chunk header: {}", err),
                )
            })?
            .0;
        let length = BigEndian::read_u64(&header);
        let mut buf = vec![0u8; length as usize];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        let data = self
            .stream
            .pull(&buf, None)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Error decoding chunk data: {}", err),
                )
            })?
            .0;
        return Ok(data);
    }
}

impl<R: Read> Read for StreamReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.buf.is_empty() {
            return Ok(self.buf.drain_into(buf));
        }
        let data = self.read_chunk()?;
        let size = min(data.len(), buf.len());
        buf[0..size].copy_from_slice(&data[0..size]);
        self.buf.put(&data[size..]);
        Ok(size)
    }
}

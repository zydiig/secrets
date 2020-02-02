use crate::sodium::secretstream;
use byteorder::{BigEndian, ByteOrder};
use std::io;
use std::io::prelude::*;
use std::mem::size_of;

pub struct StreamWriter<W: Write> {
    writer: Option<W>,
    stream: secretstream::SecretStream,
}

pub struct StreamReader<R: Read> {
    reader: Option<R>,
    stream: secretstream::SecretStream,
}

#[derive(Display)]
pub enum Error {
    IOError(io::Error),
    CryptoError(String),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

impl From<secretstream::Error> for Error {
    fn from(err: secretstream::Error) -> Self {
        Error::CryptoError(err.to_string())
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            Error::IOError(err) => err,
            Error::CryptoError(err) => io::Error::new(
                io::ErrorKind::Other,
                format!("Cryptographic error: {}", err),
            ),
        }
    }
}

const TAG_SIZE: usize = 8;

impl<W: Write> StreamWriter<W> {
    pub fn new(mut writer: W, key: &[u8]) -> Result<Self, Error> {
        let pusher = secretstream::SecretStream::new_push(key)
            .map_err(|err| Error::CryptoError(err.to_string()))?;
        writer.write_all(pusher.get_header().as_slice())?;
        Ok(Self {
            writer: Some(writer),
            stream: pusher,
        })
    }

    pub fn write_chunk(&mut self, data: &[u8], chunk_type: u8) -> Result<(), Error> {
        let mut buf = vec![0u8; size_of::<u64>() + 1];
        BigEndian::write_u64(
            &mut buf[1..],
            (data.len() + secretstream::additional_bytes_per_message()) as u64,
        );
        buf[0] = chunk_type;
        let l = self.stream.push(&buf, None, None)?;
        let c = self.stream.push(data, None, None)?;
        self.writer.as_mut().unwrap().write_all(l.as_slice())?;
        self.writer.as_mut().unwrap().write_all(c.as_slice())?;
        Ok(())
    }
}

impl<R: Read> StreamReader<R> {
    pub fn new(mut reader: R, key: &[u8]) -> Result<Self, Error> {
        let mut header = vec![0u8; secretstream::header_bytes()];
        reader.read_exact(&mut header)?;
        let puller = secretstream::SecretStream::new_pull(header.as_slice(), key)?;
        Ok(Self {
            reader: Some(reader),
            stream: puller,
        })
    }
    pub fn read_chunk(&mut self) -> Result<(Vec<u8>, u8), Error> {
        let mut encrypted_header =
            vec![0u8; 1 + size_of::<u64>() + secretstream::additional_bytes_per_message()];
        self.reader
            .as_mut()
            .unwrap()
            .read_exact(&mut encrypted_header)?;
        let header = self.stream.pull(encrypted_header.as_slice(), None)?.0;
        let length = BigEndian::read_u64(&header[1..]);
        let chunk_type = header[0];
        let mut buf = vec![0u8; length as usize];
        self.reader.as_mut().unwrap().read_exact(&mut buf)?;
        let data = self.stream.pull(&buf, None)?.0;
        Ok((data, chunk_type))
    }
}

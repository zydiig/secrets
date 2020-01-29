use std::cmp::min;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io;
use std::io::prelude::*;
use std::io::BufWriter;
use std::mem::size_of;
use std::path::Path;

use byteorder::{BigEndian, ByteOrder};

use crate::archive::object::{ObjectEpilogue, ObjectInfo};
use crate::archive::stream::StreamWriter;
use crate::buffer::Buffer;
use crate::encoding;
use crate::encoding::to_hex;
use crate::errors::Error;
use crate::sodium;
use crate::sodium::hashing::Hasher;
use crate::sodium::{aead, kdf};
use crate::sodium::{crypto_box, secretstream};
use crate::sodium::{hashing, randombytes};
use crate::streams::{ChunkType, FileHeader, FileSentinel, Stream};
use crate::zstd::{Compressor, Decompressor};
use serde::{Deserialize, Serialize};
use std::borrow::BorrowMut;
use std::fs::File;

mod object;
mod stream;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum PartType {
    Data = 0,
    Header = 1,
    Epilogue = 2,
    End = 3,
}

impl TryFrom<u8> for PartType {
    type Error = crate::errors::Error;
    fn try_from(part_type: u8) -> Result<Self, Error> {
        match part_type {
            0 => Ok(PartType::Data),
            1 => Ok(PartType::Header),
            2 => Ok(PartType::Epilogue),
            3 => Ok(PartType::End),
            _ => Err(Error::new("Invalid chunk type")),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    objects: HashMap<String, ObjectInfo>,
}

pub struct ArchiveWriter<W: Write> {
    writer: StreamWriter<W>,
    objects: HashMap<String, ObjectInfo>,
    compression_level: i32,
}

struct ObjectWriter<'a, W: Write> {
    writer: &'a mut ArchiveWriter<W>,
}

impl<W: Write> Write for ObjectWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self.writer.write_part(buf, PartType::Data) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl<W: Write> ArchiveWriter<W> {
    pub fn new(
        mut writer: W,
        sender_sk: &[u8],
        receiver_pk: &[u8],
        compression_level: i32,
    ) -> Result<Self, Error> {
        let key = randombytes(secretstream::key_bytes());
        let nonce = sodium::randombytes(crypto_box::nonce_bytes());
        let encrypted_key = crypto_box::seal_box(&key, nonce.as_slice(), receiver_pk, sender_sk);
        writer.write_all(nonce.as_slice())?;
        writer.write_all(encrypted_key.as_slice())?;
        let writer = stream::StreamWriter::new(writer, &key).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Error creating secretstream writer: {}", err),
            )
        })?;
        Ok(Self {
            writer,
            objects: HashMap::new(),
            compression_level,
        })
    }

    fn write_part(&mut self, data: &[u8], part_type: PartType) -> io::Result<()> {
        let mut part_type = [part_type as u8];
        self.writer
            .write_chunk(&part_type[..])
            .map_err(|err| io::Error::new(io::ErrorKind::Other, "Error writing part info"))?;
        self.writer
            .write_chunk(data)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, "Error writing part data"))?;
        Ok(())
    }

    fn write_object<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let mut info = ObjectInfo::from_path(path.as_ref())?;
        self.write_part(&serde_json::to_vec(&info)?, PartType::Header);
        let mut writer = ObjectWriter { writer: self };
        let mut compressor = Compressor::new(&mut writer, self.compression_level);
        let mut file = File::open(&path)?;
        let mut hasher = Hasher::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut size = 0u64;
        loop {
            let count = file.read(&mut buf)?;
            if count == 0 {
                break;
            }
            self.write_part(&buf[0..count], PartType::Data)?;
            hasher.update(&buf[0..count]);
            size += count as u64;
        }
        info.epilogue = Some(ObjectEpilogue {
            hash: to_hex(hasher.finalize()),
            size,
        });
        self.write_part(
            &serde_json::to_vec(&info.epilogue.unwrap())?,
            PartType::Epilogue,
        )?;
        Ok(())
    }
    fn end(&mut self) -> io::Result<()> {
        self.write_part(
            &serde_json::to_vec(&Manifest {
                objects: self.objects.clone(),
            })?,
            PartType::End,
        )
    }
}

impl<W: Write> Drop for ArchiveWriter<W> {
    fn drop(&mut self) {
        self.end().unwrap();
    }
}

pub struct ArchiveReader<R: Read> {
    reader: Option<R>,
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(mut reader: R, sender_pk: &[u8], receiver_sk: &[u8]) -> Result<Self, io::Error> {
        let mut nonce = vec![0u8; crypto_box::nonce_bytes()];
        reader.read_exact(nonce.as_mut_slice())?;
        let mut encrypted_key = vec![0u8; secretstream::key_bytes() + crypto_box::mac_bytes()];
        reader.read_exact(encrypted_key.as_mut_slice())?;
        let key = crypto_box::open_box(
            encrypted_key.as_slice(),
            nonce.as_slice(),
            sender_pk,
            receiver_sk,
        )?;
        let mut reader = stream::StreamReader::new(reader.borrow_mut(), &key)?;
        Ok(Self {
            reader: Some(reader),
        })
    }
}

pub struct Archive {
    stream: Stream,
    compression_level: Option<i32>,
}

struct ObjectReader<'a> {
    archive: &'a mut Archive,
    sentinel: Option<FileSentinel>,
    buf: Buffer,
}

impl Read for ObjectReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.buf.is_empty() {
            return Ok(self.buf.drain_into(buf));
        }
        let (chunk, chunk_type) = self
            .archive
            .stream
            .read_chunk()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        println!("{},{:?}", chunk.len(), chunk_type);
        match chunk_type {
            ChunkType::FileData => {
                let size = min(chunk.len(), buf.len());
                buf[0..size].copy_from_slice(&chunk[0..size]);
                self.buf.put(&chunk[size..]);
                Ok(size)
            }
            /*
            ChunkType::FileSentinel => {
                self.sentinel = Some(serde_json::from_slice(&chunk)?);
                Ok(0)
            }
            */
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected chunk type",
            )),
        }
    }
}

impl Archive {
    pub fn open<P: AsRef<Path>>(
        path: P,
        sender_pk: &[u8],
        receiver_sk: &[u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            stream: Stream::open(path, sender_pk, receiver_sk)?,
            compression_level: None,
        })
    }
    pub fn create<P: AsRef<Path>>(
        path: P,
        sender_sk: &[u8],
        receiver_pk: &[u8],
        compression_level: i32,
    ) -> Result<Self, Error> {
        Ok(Self {
            stream: Stream::create(path, sender_sk, receiver_pk)?,
            compression_level: Some(compression_level),
        })
    }
    pub fn write_object(
        &mut self,
        header: &FileHeader,
        reader: &mut dyn Read,
    ) -> Result<(), Error> {
        self.stream.write_chunk(
            serde_json::to_vec(&header)?.as_slice(),
            ChunkType::FileHeader,
        )?;
        let sentinel;
        {
            let compression_level = self.compression_level.unwrap();
            let mut writer = ObjectWriter { archive: self };
            let mut compressor = Compressor::new(
                BufWriter::with_capacity(1024 * 1024, &mut writer),
                compression_level,
            );
            let mut buf = vec![0u8; 128 * 1024];
            let mut hasher = hashing::Hasher::new();
            let mut size = 0usize;
            loop {
                let count = reader.read(&mut buf)?;
                if count == 0 {
                    break;
                }
                compressor.write_all(&buf[0..count])?;
                hasher.update(&buf[0..count]);
                size += count as usize;
            }
            compressor.finish()?;
            sentinel = FileSentinel {
                size: size as u64,
                hash: encoding::to_hex(hasher.finalize()),
            };
        }
        self.stream.write_chunk(
            serde_json::to_vec(&sentinel)?.as_slice(),
            ChunkType::FileSentinel,
        )?;
        Ok(())
    }
    pub fn read_object(&mut self, writer: &mut dyn Write) -> Result<(), Error> {
        let (chunk, chunk_type) = self.stream.read_chunk()?;
        assert_eq!(chunk_type, ChunkType::FileHeader);
        let mut reader = ObjectReader {
            archive: self,
            sentinel: None,
            buf: Buffer::with_capacity(4 * 1024 * 1024),
        };
        let mut decompressor = Decompressor::new(&mut reader);
        let mut buf = vec![0u8; 1024 * 1024];
        let mut writer = HashingWriter::new(writer);
        loop {
            let count;
            match decompressor.read(&mut buf) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(err) => return Err(From::from(err)),
                Ok(ret) => count = ret,
            };
            if count == 0 {
                break;
            }
            writer.write_all(&buf[0..count])?;
        }
        println!("{}", encoding::to_hex(writer.get_hash()));
        let (chunk, chunk_type) = self.stream.read_chunk()?;
        let sentinel: FileSentinel = serde_json::from_slice(&chunk)?;
        println!("{:?}", sentinel);
        Ok(())
    }
}

struct HashingWriter<W: Write> {
    inner: Option<W>,
    hasher: hashing::Hasher,
}

impl<W: Write> HashingWriter<W> {
    fn new(writer: W) -> Self {
        Self {
            inner: Some(writer),
            hasher: hashing::Hasher::new(),
        }
    }
    fn get_hash(&mut self) -> Vec<u8> {
        self.hasher.finalize()
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.inner.as_mut().unwrap().write(buf).and_then(|count| {
            self.hasher.update(&buf[0..count]);
            Ok(count)
        })
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.inner.as_mut().unwrap().flush()
    }
}

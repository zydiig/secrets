use std::cmp::min;
use std::convert::TryFrom;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::ops::Deref;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::archive::object::{ObjectEpilogue, ObjectInfo, ObjectType};
use crate::buffer::Buffer;
use crate::errors::Error;
use crate::sodium;
use crate::sodium::hashing::Hasher;
use crate::sodium::pwhash;
use crate::sodium::randombytes;
use crate::sodium::secretstream::SecretStream;
use crate::sodium::{aead, kdf};
use crate::sodium::{crypto_box, secretstream};
use crate::zstd::{Compressor, Decompressor};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use std::mem::size_of;

pub mod object;

const OPSLIMIT: u64 = 3;
const MEMLIMIT: usize = 1024 * 1024 * 1024;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ChunkType {
    Data = 0,
    Header = 1,
    Epilogue = 2,
    End = 3,
}

impl TryFrom<u8> for ChunkType {
    type Error = crate::errors::Error;
    fn try_from(part_type: u8) -> Result<Self, Error> {
        match part_type {
            0 => Ok(ChunkType::Data),
            1 => Ok(ChunkType::Header),
            2 => Ok(ChunkType::Epilogue),
            3 => Ok(ChunkType::End),
            _ => Err(Error::new("Invalid chunk type")),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    objects: Vec<ObjectInfo>,
}

pub struct ArchiveWriter<W: Write> {
    writer: Option<W>,
    pusher: SecretStream,
    objects: Vec<ObjectInfo>,
    compression_level: i32,
}

struct ObjectWriter<'a, W: Write> {
    writer: &'a mut ArchiveWriter<W>,
}

impl<W: Write> Write for ObjectWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self.writer.write_chunk(buf, ChunkType::Data) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl<W: Write> ArchiveWriter<W> {
    pub fn new(mut writer: W, password: &str, compression_level: i32) -> Result<Self, io::Error> {
        let salt = randombytes(pwhash::SALT_BYTES);
        writer.write_all(&salt)?;
        let key =
            pwhash::pwhash(password, secretstream::KEY_BYTES, &salt, OPSLIMIT, MEMLIMIT).unwrap();
        let mut params = vec![0u8; 2 * size_of::<u64>()];
        BigEndian::write_u64_into(&[OPSLIMIT, MEMLIMIT as u64], &mut params);
        writer.write_all(&params)?;
        let pusher = secretstream::SecretStream::new_push(&key).unwrap();
        writer.write_all(&pusher.get_header())?;
        Ok(Self {
            writer: Some(writer),
            pusher,
            objects: Vec::new(),
            compression_level,
        })
    }

    fn write_chunk(&mut self, data: &[u8], part_type: ChunkType) -> io::Result<()> {
        let mut info = [0u8; size_of::<u32>() + 1];
        info[0] = part_type as u8;
        let clen = data.len() + secretstream::ADDITIONAL_BYTES;
        BigEndian::write_u32(&mut info[1..], clen as u32);
        let encrypted_info = self.pusher.push(&info, None, None).unwrap();
        let encrypted_data = self.pusher.push(data, None, None).unwrap();
        assert_eq!(encrypted_data.len(), clen);
        assert!(encrypted_data.len() as u64 <= std::u32::MAX as u64);
        let writer = self.writer.as_mut().unwrap();
        writer.write_all(&encrypted_info)?;
        writer.write_all(&encrypted_data)?;
        Ok(())
    }

    pub fn write_object<P: AsRef<Path>>(
        &mut self,
        path: P,
        object_path: &[String],
    ) -> io::Result<()> {
        let mut info = ObjectInfo::from_path(path.as_ref(), object_path)?;
        self.write_chunk(&serde_json::to_vec(&info)?, ChunkType::Header)?;
        if info.object_type == ObjectType::Directory {
            return Ok(());
        }
        let mut compressor = Compressor::new(self.compression_level);
        let mut file = File::open(&path)?;
        let mut hasher = Hasher::new();
        let mut buf = vec![0u8; 2 * 1024 * 1024];
        let mut size = 0u64;
        loop {
            let count = file.read(&mut buf)?;
            if count == 0 {
                break;
            }
            let compressed = compressor.compress(&buf[0..count]).unwrap();
            if !compressed.is_empty() {
                self.write_chunk(compressed, ChunkType::Data)?;
            }
            hasher.update(&buf[0..count]);
            size += count as u64;
        }
        self.write_chunk(compressor.finish().unwrap(), ChunkType::Data)?;
        info.epilogue = Some(ObjectEpilogue {
            hash: sodium::to_hex(&hasher.finalize()),
            size,
        });
        self.write_chunk(
            &serde_json::to_vec(info.epilogue.as_ref().unwrap())?,
            ChunkType::Epilogue,
        )?;
        self.objects.push(info);
        Ok(())
    }
    pub fn end(&mut self) -> io::Result<()> {
        self.write_chunk(
            &serde_json::to_vec(&Manifest {
                objects: self.objects.clone(),
            })?,
            ChunkType::End,
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
    puller: SecretStream,
    manifest: Option<Manifest>,
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(mut reader: R, password: &str) -> Result<Self, io::Error> {
        let mut salt = vec![0u8; pwhash::SALT_BYTES];
        reader.read_exact(&mut salt)?;
        let opslimit = reader.read_u64::<BigEndian>()?;
        let memlimit = reader.read_u64::<BigEndian>()?;
        let key = pwhash::pwhash(
            password,
            secretstream::KEY_BYTES,
            &salt,
            opslimit,
            memlimit as usize,
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        let mut header = vec![0u8; secretstream::HEADER_BYTES];
        reader.read_exact(&mut header)?;
        let puller = secretstream::SecretStream::new_pull(&header, &key).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Error opening secretstream for read")
        })?;
        Ok(Self {
            reader: Some(reader),
            puller,
            manifest: None,
        })
    }

    pub fn read_object(&mut self) -> io::Result<Option<ObjectReader<R>>> {
        let (part_type, part) = self.read_chunk()?;
        if part_type == ChunkType::End {
            self.manifest = Some(serde_json::from_slice(&part)?);
            return Ok(None);
        }
        let info: ObjectInfo = serde_json::from_slice(part.deref()).unwrap();
        Ok(Some(ObjectReader {
            archive: self,
            object_info: info,
            buf: Buffer::with_capacity(1024 * 1024),
            object_epilogue: None,
            decompressor: Decompressor::new(),
        }))
    }

    pub fn read_chunk(&mut self) -> io::Result<(ChunkType, Vec<u8>)> {
        let reader = self.reader.as_mut().unwrap();
        let mut encrypted_info = [0u8; 1 + size_of::<u32>() + secretstream::ADDITIONAL_BYTES];
        reader.read_exact(&mut encrypted_info)?;
        let (info, _) = self
            .puller
            .pull(&encrypted_info, None)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error decrypting chunk info"))?;
        let clen = BigEndian::read_u32(&info[1..]);
        let mut ciphertext = vec![0u8; clen as usize];
        reader.read_exact(&mut ciphertext)?;
        let (chunk, _) = self
            .puller
            .pull(&ciphertext, None)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error decrypting chunk data"))?;
        let chunk_type = ChunkType::try_from(info[0]).unwrap();
        Ok((chunk_type, chunk))
    }
}

pub struct ObjectReader<'a, R: Read> {
    archive: &'a mut ArchiveReader<R>,
    pub object_info: ObjectInfo,
    buf: Buffer,
    pub object_epilogue: Option<ObjectEpilogue>,
    decompressor: Decompressor,
}

impl<R: Read> Read for ObjectReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if buf.is_empty() || self.object_epilogue.is_some() {
            return Ok(0);
        }
        if !self.buf.is_empty() {
            return Ok(self.buf.drain_into(buf));
        }
        let (part_type, part) = self.archive.read_chunk()?;
        match part_type {
            ChunkType::Data => {
                let data = self.decompressor.decompress(&part).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Error decompressing data: {}", err),
                    )
                })?;
                let size = min(data.len(), buf.len());
                if size == 0 {
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                buf[0..size].copy_from_slice(&data[0..size]);
                self.buf.put(&data[size..]);
                Ok(size)
            }
            ChunkType::Epilogue => {
                self.object_epilogue = Some(serde_json::from_slice(&part)?);
                Ok(0)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Unexpected part type: {:?}", part_type),
            )),
        }
    }
}

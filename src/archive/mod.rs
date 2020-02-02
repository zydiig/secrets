use std::cmp::min;
use std::convert::TryFrom;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::ops::Deref;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::archive::object::{ObjectEpilogue, ObjectInfo, ObjectType};
use crate::archive::stream::{StreamReader, StreamWriter};
use crate::buffer::Buffer;
use crate::encoding::to_hex;
use crate::errors::Error;
use crate::sodium;
use crate::sodium::hashing::Hasher;
use crate::sodium::randombytes;
use crate::sodium::{aead, kdf};
use crate::sodium::{crypto_box, secretstream};
use crate::zstd::{Compressor, Decompressor};

pub mod object;
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
    objects: Vec<ObjectInfo>,
}

pub struct ArchiveWriter<W: Write> {
    writer: StreamWriter<W>,
    objects: Vec<ObjectInfo>,
    compression_level: i32,
}

struct ObjectWriter<'a, W: Write> {
    writer: &'a mut ArchiveWriter<W>,
}

impl<W: Write> Write for ObjectWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self.writer.write_part(buf, PartType::Data) {
            Ok(_) => Ok(buf.len()),
            Err(e) => Err(e.into()),
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
            objects: Vec::new(),
            compression_level,
        })
    }

    fn write_part(&mut self, data: &[u8], part_type: PartType) -> io::Result<()> {
        self.writer
            .write_chunk(data, part_type as u8)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Error writing part data: {}", err),
                )
            })?;
        Ok(())
    }

    pub fn write_object<P: AsRef<Path>>(
        &mut self,
        path: P,
        object_path: &[String],
    ) -> io::Result<()> {
        let mut info = ObjectInfo::from_path(path.as_ref(), object_path)?;
        self.write_part(&serde_json::to_vec(&info)?, PartType::Header)?;
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
                self.write_part(compressed, PartType::Data)?;
            }
            hasher.update(&buf[0..count]);
            size += count as u64;
        }
        self.write_part(compressor.finish().unwrap(), PartType::Data)?;
        info.epilogue = Some(ObjectEpilogue {
            hash: to_hex(hasher.finalize()),
            size,
        });
        self.write_part(
            &serde_json::to_vec(info.epilogue.as_ref().unwrap())?,
            PartType::Epilogue,
        )?;
        self.objects.push(info);
        Ok(())
    }
    pub fn end(&mut self) -> io::Result<()> {
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
    reader: StreamReader<R>,
    manifest: Option<Manifest>,
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
        )
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "error decrypting session key"))?;
        let reader =
            stream::StreamReader::new(reader, &key).map_err(|err| Into::<io::Error>::into(err))?;
        Ok(Self {
            reader,
            manifest: None,
        })
    }

    pub fn read_object(&mut self) -> io::Result<Option<ObjectReader<R>>> {
        let (part_type, part) = self.read_part()?;
        if part_type == PartType::End {
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

    pub fn read_part(&mut self) -> io::Result<(PartType, Vec<u8>)> {
        let (chunk, chunk_type) = self
            .reader
            .read_chunk()
            .map_err(|err| Into::<io::Error>::into(err))?;
        let part_type = PartType::try_from(chunk_type).unwrap();
        Ok((part_type, chunk))
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
        let (part_type, part) = self.archive.read_part()?;
        match part_type {
            PartType::Data => {
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
            PartType::Epilogue => {
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

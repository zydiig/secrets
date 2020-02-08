use std::cmp::min;
use std::convert::TryFrom;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::archive::object::{ObjectEpilogue, ObjectInfo, ObjectType};
use crate::buffer::Buffer;
use crate::sodium;
use crate::sodium::hashing::Hasher;
use crate::sodium::pwhash;
use crate::sodium::randombytes;
use crate::sodium::secretstream::SecretStream;
use crate::sodium::{aead, kdf};
use crate::sodium::{crypto_box, secretstream};
use crate::zstd::{Compressor, Decompressor};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use failure::{ensure, err_msg, format_err, Error, ResultExt};
use std::mem::size_of;

pub mod object;

const OPSLIMIT: u64 = 3;
const MEMLIMIT: usize = 1024 * 1024 * 1024;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ChunkType {
    Data = 0,
    Header = 1,
    Epilogue = 2,
    VolumeEnd = 3,
    End = 4,
}

impl TryFrom<u8> for ChunkType {
    type Error = Error;
    fn try_from(part_type: u8) -> Result<Self, Error> {
        match part_type {
            0 => Ok(ChunkType::Data),
            1 => Ok(ChunkType::Header),
            2 => Ok(ChunkType::Epilogue),
            3 => Ok(ChunkType::VolumeEnd),
            4 => Ok(ChunkType::End),
            _ => Err(err_msg("Invalid chunk type")),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    objects: Vec<ObjectInfo>,
}

fn get_real_path<P: AsRef<Path>>(path: P, volume_counter: u64) -> Result<PathBuf, Error> {
    let mut filename = path
        .as_ref()
        .file_name()
        .ok_or_else(|| err_msg("Error getting filename component"))?
        .to_owned();
    filename.push(format!(".{:03}", volume_counter));
    Ok(path.as_ref().with_file_name(filename))
}

pub struct ArchiveWriter {
    file: File,
    pusher: SecretStream,
    objects: Vec<ObjectInfo>,
    compression_level: i32,
    volume_counter: u64,
    volume_size: Option<u64>,
    byte_count: u64,
    raw_path: PathBuf,
    ended: bool,
}

impl ArchiveWriter {
    pub fn new<P: AsRef<Path>>(
        path: P,
        password: &str,
        compression_level: i32,
        volume_size: Option<u64>,
    ) -> Result<Self, Error> {
        let mut file = match volume_size {
            Some(_) => {
                File::create(get_real_path(path.as_ref(), 1)?).context("Error opening file")?
            }
            None => File::create(path.as_ref()).context("Error opening file")?,
        };
        let mut byte_count = 0u64;
        let salt = randombytes(pwhash::SALT_BYTES);
        file.write_all(&salt)?;
        byte_count += salt.len() as u64;
        let key = pwhash::pwhash(password, secretstream::KEY_BYTES, &salt, OPSLIMIT, MEMLIMIT)
            .context("Error deriving key from password")
            .unwrap();
        let mut params = vec![0u8; 2 * size_of::<u64>()];
        BigEndian::write_u64_into(&[OPSLIMIT, MEMLIMIT as u64], &mut params);
        file.write_all(&params)?;
        byte_count += params.len() as u64;
        let pusher = secretstream::SecretStream::new_push(&key).unwrap();
        file.write_all(&pusher.get_header())?;
        byte_count += pusher.get_header().len() as u64;
        Ok(Self {
            file,
            pusher,
            objects: Vec::new(),
            compression_level,
            volume_counter: 1,
            volume_size,
            byte_count,
            raw_path: path.as_ref().to_path_buf(),
            ended: false,
        })
    }

    fn write_chunk_unchecked(&mut self, data: &[u8], part_type: ChunkType) -> Result<u64, Error> {
        let mut info = [0u8; size_of::<u32>() + 1];
        info[0] = part_type as u8;
        let clen = data.len() + secretstream::ADDITIONAL_BYTES;
        BigEndian::write_u32(&mut info[1..], clen as u32);
        let encrypted_info = self.pusher.push(&info, None, None).unwrap();
        let encrypted_data = self.pusher.push(data, None, None).unwrap();
        assert_eq!(encrypted_data.len(), clen);
        assert!(encrypted_data.len() as u64 <= std::u32::MAX as u64);
        self.file.write_all(&encrypted_info)?;
        self.file.write_all(&encrypted_data)?;
        Ok((encrypted_info.len() + encrypted_data.len()) as u64)
    }

    fn write_chunk(&mut self, data: &[u8], part_type: ChunkType) -> Result<(), Error> {
        if let Some(volume_size) = self.volume_size {
            let chunk_size = (4
                + 1
                + secretstream::ADDITIONAL_BYTES
                + data.len()
                + secretstream::ADDITIONAL_BYTES) as u64;
            let extra_size =
                (4 + 1 + secretstream::ADDITIONAL_BYTES + 1024 + secretstream::ADDITIONAL_BYTES)
                    as u64;
            if self.byte_count + chunk_size + extra_size > volume_size - 4 * 1024 {
                self.write_chunk_unchecked(&[], ChunkType::VolumeEnd)
                    .context("Error writing VolumeEnd chunk")?;
                self.file = File::create(get_real_path(&self.raw_path, self.volume_counter + 1)?)
                    .context("Error creating next volume")?;
                self.volume_counter += 1;
                self.byte_count = 0;
            }
        }
        self.byte_count += self.write_chunk_unchecked(data, part_type)?;
        Ok(())
    }

    pub fn write_object<P: AsRef<Path>>(
        &mut self,
        path: P,
        object_path: &[String],
    ) -> Result<(), Error> {
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
    pub fn end(&mut self) -> Result<(), Error> {
        if !self.ended {
            self.ended = true;
            self.write_chunk(
                &serde_json::to_vec(&Manifest {
                    objects: self.objects.clone(),
                })?,
                ChunkType::End,
            )?;
        }
        Ok(())
    }
}

impl Drop for ArchiveWriter {
    fn drop(&mut self) {
        self.end().unwrap();
    }
}

pub struct ArchiveReader {
    file: File,
    puller: SecretStream,
    pub manifest: Option<Manifest>,
    raw_path: PathBuf,
    volume_counter: Option<u64>,
}

impl ArchiveReader {
    pub fn new<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, Error> {
        let mut file = File::open(path.as_ref()).context("Error opening archive for read")?;
        let mut salt = vec![0u8; pwhash::SALT_BYTES];
        file.read_exact(&mut salt)
            .context("Error reading password hashing salt")?;
        let opslimit = file.read_u64::<BigEndian>()?;
        let memlimit = file.read_u64::<BigEndian>()?;
        let key = pwhash::pwhash(
            password,
            secretstream::KEY_BYTES,
            &salt,
            opslimit,
            memlimit as usize,
        )
        .context("Error deriving archive key")?;
        let mut header = vec![0u8; secretstream::HEADER_BYTES];
        file.read_exact(&mut header)?;
        let puller = secretstream::SecretStream::new_pull(&header, &key)
            .context("Error opening secretstream for read")?;
        Ok(Self {
            file,
            puller,
            manifest: None,
            raw_path: path.as_ref().to_path_buf(),
            volume_counter: None,
        })
    }

    pub fn read_object(&mut self) -> Result<Option<ObjectReader>, Error> {
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

    fn open_next_volume(&mut self) -> Result<(), Error> {
        let mut filename = self
            .raw_path
            .file_name()
            .ok_or_else(|| err_msg("Error getting filename component"))?
            .to_str()
            .ok_or_else(|| err_msg("Error decoding filename"))?
            .to_owned();
        ensure!(filename.ends_with(".001"), "Invalid filename");
        if self.volume_counter.is_none() {
            self.volume_counter = Some(1);
        }
        self.volume_counter = Some(self.volume_counter.unwrap() + 1);
        filename.truncate(filename.len() - 4);
        filename.push_str(&format!(".{:03}", self.volume_counter.unwrap()));
        self.file = File::open(&self.raw_path.with_file_name(filename))
            .context("Error opening next volume")?;
        Ok(())
    }

    pub fn read_chunk(&mut self) -> Result<(ChunkType, Vec<u8>), Error> {
        let mut encrypted_info = [0u8; 1 + size_of::<u32>() + secretstream::ADDITIONAL_BYTES];
        self.file.read_exact(&mut encrypted_info)?;
        let (info, _) = self
            .puller
            .pull(&encrypted_info, None)
            .context("Error decrypting chunk info")?;
        let chunk_type = ChunkType::try_from(info[0]).unwrap();
        let clen = BigEndian::read_u32(&info[1..]);
        let mut ciphertext = vec![0u8; clen as usize];
        self.file.read_exact(&mut ciphertext)?;
        let (chunk, _) = self
            .puller
            .pull(&ciphertext, None)
            .context("Error decrypting chunk data")?;
        println!("type={:?}, len={}", chunk_type, chunk.len());
        if chunk_type == ChunkType::VolumeEnd {
            self.open_next_volume()?;
            return self.read_chunk();
        }
        Ok((chunk_type, chunk))
    }
}

pub struct ObjectReader<'a> {
    archive: &'a mut ArchiveReader,
    pub object_info: ObjectInfo,
    buf: Buffer,
    pub object_epilogue: Option<ObjectEpilogue>,
    decompressor: Decompressor,
}

impl ObjectReader<'_> {
    pub fn read_data(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let (part_type, part) = self.archive.read_chunk()?;
        match part_type {
            ChunkType::Data => {
                let data = self
                    .decompressor
                    .decompress(&part)
                    .context("Error decompressing data")?;
                Ok(Some(data.to_vec()))
            }
            ChunkType::Epilogue => {
                self.object_epilogue = Some(serde_json::from_slice(&part)?);
                Ok(None)
            }
            _ => Err(format_err!("Unexpected part type: {:?}", part_type)),
        }
    }
}

impl Read for ObjectReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if buf.is_empty() || self.object_epilogue.is_some() {
            return Ok(0);
        }
        if !self.buf.is_empty() {
            return Ok(self.buf.drain_into(buf));
        }
        let data = self
            .read_data()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        match data {
            Some(data) => {
                if data.is_empty() {
                    Err(io::Error::new(io::ErrorKind::Interrupted, "Read again"))
                } else {
                    let size = min(buf.len(), data.len());
                    buf[0..size].copy_from_slice(&data[0..size]);
                    self.buf.put(&data[size..]);
                    Ok(size)
                }
            }
            None => Ok(0),
        }
    }
}

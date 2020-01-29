use crate::errors::Error;
use crate::sodium;
use crate::sodium::crypto_box;
use crate::sodium::secretstream;
use byteorder::{BigEndian, ByteOrder};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::mem::size_of;
use std::path::Path;

#[derive(PartialEq, Eq, Debug)]
pub enum StreamMode {
    Read,
    Write,
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ChunkType {
    FileData = 0,
    FileHeader = 1,
    FileSentinel = 2,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileHeader {
    pub name: String,
    pub path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileSentinel {
    pub hash: String,
    pub size: u64,
}

pub struct Stream {
    file: File,
    mode: StreamMode,
    stream: secretstream::SecretStream,
}

impl TryFrom<u8> for ChunkType {
    type Error = crate::errors::Error;
    fn try_from(chunk_type: u8) -> Result<Self, Error> {
        match chunk_type {
            0 => Ok(ChunkType::FileData),
            1 => Ok(ChunkType::FileHeader),
            2 => Ok(ChunkType::FileSentinel),
            _ => Err(Error::new("Invalid chunk type")),
        }
    }
}

impl Stream {
    pub fn open<P: AsRef<Path>>(
        path: P,
        sender_pk: &[u8],
        receiver_sk: &[u8],
    ) -> Result<Self, Error> {
        let mut file = File::open(path)?;
        let mut nonce = vec![0u8; crypto_box::nonce_bytes()];
        file.read_exact(nonce.as_mut_slice())?;
        let mut encrypted_key = vec![0u8; secretstream::key_bytes() + crypto_box::mac_bytes()];
        file.read_exact(encrypted_key.as_mut_slice())?;
        let key = crypto_box::open_box(
            encrypted_key.as_slice(),
            nonce.as_slice(),
            sender_pk,
            receiver_sk,
        )?;
        let mut header = vec![0u8; secretstream::header_bytes()];
        file.read_exact(header.as_mut_slice())?;
        let puller = secretstream::SecretStream::new_pull(header.as_slice(), key.as_slice())?;
        Ok(Self {
            file,
            mode: StreamMode::Read,
            stream: puller,
        })
    }

    pub fn read_chunk(&mut self) -> Result<(Vec<u8>, ChunkType), Error> {
        if self.mode != StreamMode::Read {
            return Err("Wrong file mode".into());
        }
        let mut encrypted_info =
            vec![0u8; 1 + size_of::<u64>() + secretstream::additional_bytes_per_message()];
        self.file.read_exact(&mut encrypted_info)?;
        let info = self.stream.pull(encrypted_info.as_slice(), None)?.0;
        let length = BigEndian::read_u64(&info[1..]);
        let chunk_type = ChunkType::try_from(info[0])?;
        let mut buf = vec![0u8; length as usize];
        self.file.read_exact(buf.as_mut_slice())?;
        let data = self.stream.pull(buf.as_slice(), None)?.0;
        println!("type={:?}, len={}", chunk_type, data.len());
        Ok((data, chunk_type))
    }

    pub fn write_chunk(&mut self, data: &[u8], chunk_type: ChunkType) -> Result<(), Error> {
        if self.mode != StreamMode::Write {
            return Err("Wrong file mode".into());
        }
        let mut buf = vec![0u8; 1 + size_of::<u64>()];
        BigEndian::write_u64(
            &mut buf[1..],
            (data.len() + secretstream::additional_bytes_per_message()) as u64,
        );
        buf[0] = chunk_type as u8;
        let l = self.stream.push(&buf, None, None)?;
        let c = self.stream.push(data, None, None)?;
        self.file.write_all(l.as_slice())?;
        self.file.write_all(c.as_slice())?;
        println!("type={:?}, len={}", chunk_type, data.len());
        Ok(())
    }

    pub fn create<P: AsRef<Path>>(
        path: P,
        sender_sk: &[u8],
        receiver_pk: &[u8],
    ) -> Result<Self, Error> {
        let mut file = File::create(path)?;
        let key = secretstream::generate_key();
        let nonce = sodium::randombytes(crypto_box::nonce_bytes());
        let encrypted_key =
            crypto_box::seal_box(key.as_slice(), nonce.as_slice(), receiver_pk, sender_sk);
        file.write_all(nonce.as_slice())?;
        file.write_all(encrypted_key.as_slice())?;
        let pusher = secretstream::SecretStream::new_push(&key)?;
        file.write_all(pusher.get_header().as_slice())?;
        Ok(Self {
            file,
            mode: StreamMode::Write,
            stream: pusher,
        })
    }
}

use crate::encoding::Base64Data;
use crate::errors::Error;
use crate::sodium;
use crate::sodium::crypto_box;
use crate::sodium::secretstream;
use byteorder::{BigEndian, ByteOrder};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

#[derive(PartialEq, Eq, Debug)]
pub enum StreamMode {
    Read,
    Write,
}

pub struct FileHeader {
    name: String,
    path: String,
    size: u64,
}

pub struct FileSentinel {

}

pub struct Stream {
    file: File,
    mode: StreamMode,
    stream: secretstream::SecretStream,
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

    pub fn read_chunk(&mut self) -> Result<Vec<u8>, Error> {
        if self.mode != StreamMode::Read {
            return Err("Wrong file mode".into());
        }
        let mut encrypted_length = vec![0u8; 8 + secretstream::additional_bytes_per_message()];
        let count = self.file.read(encrypted_length.as_mut_slice())?;
        if count != encrypted_length.len() {
            return Err(Error::new("Unexpected EOF"));
        }
        let length = BigEndian::read_u64(
            self.stream
                .pull(encrypted_length.as_slice(), None)?
                .0
                .as_slice(),
        );
        let mut buf = vec![0u8; length as usize];
        if length == secretstream::additional_bytes_per_message() as u64 {
            return Ok(vec![0u8; 0]);
        }
        self.file.read_exact(buf.as_mut_slice())?;
        let data = self.stream.pull(buf.as_slice(), None)?.0;
        Ok(data)
    }

    pub fn write_chunk(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.mode != StreamMode::Write {
            return Err("Wrong file mode".into());
        }
        let mut length = vec![0u8; 8];
        BigEndian::write_u64(
            length.as_mut_slice(),
            (data.len() + secretstream::additional_bytes_per_message()) as u64,
        );
        let l = self.stream.push(&length, None, None)?;
        let c = self.stream.push(data, None, None)?;
        self.file.write_all(l.as_slice())?;
        self.file.write_all(c.as_slice())?;
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

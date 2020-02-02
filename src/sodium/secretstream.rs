use super::_sodium;
use serde::export::Formatter;
use std::alloc::{alloc, Layout};
use std::convert::TryFrom;
use std::fmt::Display;
use std::mem::align_of;

pub const fn additional_bytes_per_message() -> usize {
    _sodium::crypto_secretstream_xchacha20poly1305_ABYTES as usize
}

pub const fn key_bytes() -> usize {
    _sodium::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize
}

pub const fn header_bytes() -> usize {
    _sodium::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize
}

#[derive(Display, Debug, Clone, Copy)]
pub enum Error {
    InvalidKey,
    InvalidTag,
    InvalidCiphertext,
    MessageTooLong,
    InvalidStreamHeader,
    WrongStreamMode,
}

#[derive(PartialEq, Eq)]
pub enum Direction {
    Push,
    Pull,
}

#[derive(PartialEq, Eq)]
pub enum MessageTag {
    Message,
    Push,
    Rekey,
    Final,
}

impl TryFrom<u8> for MessageTag {
    type Error = Error;
    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag as u32 {
            _sodium::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE => Ok(MessageTag::Message),
            _sodium::crypto_secretstream_xchacha20poly1305_TAG_PUSH => Ok(MessageTag::Push),
            _sodium::crypto_secretstream_xchacha20poly1305_TAG_REKEY => Ok(MessageTag::Rekey),
            _sodium::crypto_secretstream_xchacha20poly1305_TAG_FINAL => Ok(MessageTag::Final),
            _ => Err(Error::InvalidTag),
        }
    }
}

impl Into<u8> for MessageTag {
    fn into(self) -> u8 {
        (match self {
            MessageTag::Message => _sodium::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
            MessageTag::Push => _sodium::crypto_secretstream_xchacha20poly1305_TAG_PUSH,
            MessageTag::Rekey => _sodium::crypto_secretstream_xchacha20poly1305_TAG_REKEY,
            MessageTag::Final => _sodium::crypto_secretstream_xchacha20poly1305_TAG_FINAL,
        } as u8)
    }
}

type InternalState = _sodium::crypto_secretstream_xchacha20poly1305_state;

pub struct SecretStream {
    state: *mut InternalState,
    header: Vec<u8>,
    dir: Direction,
}

pub fn generate_key() -> Vec<u8> {
    unsafe {
        let mut key = vec![0u8; _sodium::crypto_secretstream_xchacha20poly1305_keybytes()];
        _sodium::crypto_secretstream_xchacha20poly1305_keygen(key.as_mut_ptr());
        key
    }
}

impl Drop for SecretStream {
    fn drop(&mut self) {
        unsafe {
            std::alloc::dealloc(
                self.state as *mut u8,
                Layout::from_size_align(
                    _sodium::crypto_secretstream_xchacha20poly1305_statebytes(),
                    align_of::<u8>(),
                )
                .expect("Bad memory layout"),
            );
        }
    }
}

impl SecretStream {
    fn alloc_state() -> *mut InternalState {
        unsafe {
            (alloc(
                Layout::from_size_align(
                    _sodium::crypto_secretstream_xchacha20poly1305_statebytes(),
                    align_of::<u8>(),
                )
                .expect("Bad memory layout"),
            ) as *mut InternalState)
        }
    }

    pub fn get_header(&self) -> Vec<u8> {
        self.header.clone()
    }

    pub fn new_push(key: &[u8]) -> Result<SecretStream, Error> {
        unsafe {
            if key.len() != _sodium::crypto_secretstream_xchacha20poly1305_keybytes() {
                return Err(Error::InvalidKey);
            }
            let state = SecretStream::alloc_state();
            let mut header =
                vec![0u8; _sodium::crypto_secretstream_xchacha20poly1305_headerbytes()];
            _sodium::crypto_secretstream_xchacha20poly1305_init_push(
                state,
                header.as_mut_ptr(),
                key.as_ptr(),
            );
            Ok(SecretStream {
                state,
                header,
                dir: Direction::Push,
            })
        }
    }

    pub fn new_pull(header: &[u8], key: &[u8]) -> Result<SecretStream, Error> {
        unsafe {
            let state = SecretStream::alloc_state();
            match _sodium::crypto_secretstream_xchacha20poly1305_init_pull(
                state,
                header.as_ptr(),
                key.as_ptr(),
            ) {
                0 => Ok(SecretStream {
                    state,
                    header: Vec::from(header),
                    dir: Direction::Pull,
                }),
                _ => Err(Error::InvalidStreamHeader),
            }
        }
    }

    pub fn push(
        &self,
        data: &[u8],
        ad: Option<&[u8]>,
        tag: Option<MessageTag>,
    ) -> Result<Vec<u8>, Error> {
        unsafe {
            if self.dir != Direction::Push {
                return Err(Error::WrongStreamMode);
            }
            if data.len() > _sodium::crypto_secretstream_xchacha20poly1305_messagebytes_max() {
                return Err(Error::MessageTooLong);
            }
            let mut ciphertext =
                vec![0u8; data.len() + _sodium::crypto_secretstream_xchacha20poly1305_abytes()];
            let tag: u8 = tag.unwrap_or(MessageTag::Message).into();
            let (ad, adlen) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len() as u64),
                None => (std::ptr::null::<u8>(), 0),
            };
            let mut clen: u64 = 0;
            _sodium::crypto_secretstream_xchacha20poly1305_push(
                self.state,
                ciphertext.as_mut_ptr(),
                &mut clen as *mut u64,
                data.as_ptr(),
                data.len() as u64,
                ad,
                adlen,
                tag,
            );
            assert!(clen > 0);
            ciphertext.truncate(clen as usize);
            Ok(ciphertext)
        }
    }

    pub fn pull(
        &self,
        ciphertext: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, MessageTag), Error> {
        unsafe {
            if ciphertext.len() < _sodium::crypto_secretstream_xchacha20poly1305_abytes() {
                return Err(Error::InvalidCiphertext);
            }
            let mut plaintext = vec![
                0u8;
                ciphertext.len()
                    - _sodium::crypto_secretstream_xchacha20poly1305_abytes()
            ];
            let mut tag = 0u8;
            let (ad, adlen) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len() as u64),
                None => (std::ptr::null(), 0),
            };
            let mut mlen: u64 = 0;
            match _sodium::crypto_secretstream_xchacha20poly1305_pull(
                self.state,
                plaintext.as_mut_ptr(),
                &mut mlen as *mut u64,
                &mut tag,
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad,
                adlen,
            ) {
                0 => {
                    plaintext.truncate(mlen as usize);
                    Ok((plaintext, MessageTag::try_from(tag)?))
                }
                _ => Err(Error::InvalidCiphertext),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sodium::randombytes;
    use crate::sodium::secretstream;
    use std::time::{Duration, Instant};

    fn stream_perf_test_size(size: usize) {
        let key = secretstream::generate_key();
        let pusher = secretstream::SecretStream::new_push(&key).unwrap();
        let puller = secretstream::SecretStream::new_pull(&pusher.get_header(), &key).unwrap();
        let input = randombytes(size);
        let iterations = 4000;
        let start = Instant::now();
        for i in 1..=iterations {
            let c = pusher.push(&input, None, None);
        }
        let time = Instant::now().duration_since(start).as_secs_f64();
        println!(
            "size={}, speed={}",
            size,
            (size * iterations) as f64 / time / 1024.0 / 1024.0
        );
    }

    #[test]
    fn perf_test() {
        for size in &[1024, 4096, 8192, 16384, 65536] {
            stream_perf_test_size(*size);
        }
    }

    #[test]
    fn stream_test() {
        let key = secretstream::generate_key();
        let pusher = secretstream::SecretStream::new_push(&key).unwrap();
        let puller = secretstream::SecretStream::new_pull(&pusher.get_header(), &key).unwrap();
        let input = randombytes(1024);
        for i in 1..100 {
            let c = pusher
                .push(&input, None, Some(secretstream::MessageTag::Message))
                .unwrap();
            let (p, tag) = puller.pull(&c, None).unwrap();
            assert_eq!(p, input);
        }
    }
}

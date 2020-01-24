use super::_sodium;

use std::alloc::{alloc, Layout};
use std::convert::TryFrom;
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
    type Error = &'static str;
    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag as u32 {
            _sodium::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE => Ok(MessageTag::Message),
            _sodium::crypto_secretstream_xchacha20poly1305_TAG_PUSH => Ok(MessageTag::Push),
            _sodium::crypto_secretstream_xchacha20poly1305_TAG_REKEY => Ok(MessageTag::Rekey),
            _sodium::crypto_secretstream_xchacha20poly1305_TAG_FINAL => Ok(MessageTag::Final),
            _ => Err("Invalid tag"),
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

    pub fn new_push(key: &[u8]) -> Result<SecretStream, &'static str> {
        unsafe {
            if key.len() != _sodium::crypto_secretstream_xchacha20poly1305_keybytes() {
                return Err("Invalid key length");
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

    pub fn new_pull(header: &[u8], key: &[u8]) -> Result<SecretStream, &'static str> {
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
                _ => Err("Invalid header"),
            }
        }
    }

    pub fn push(
        &self,
        data: &[u8],
        ad: Option<&[u8]>,
        tag: Option<MessageTag>,
    ) -> Result<Vec<u8>, &'static str> {
        unsafe {
            if self.dir != Direction::Push {
                return Err("Stream is in Push mode");
            }
            if data.len() > _sodium::crypto_secretstream_xchacha20poly1305_messagebytes_max() {
                return Err("Message too long");
            }
            let mut ciphertext =
                vec![0u8; data.len() + _sodium::crypto_secretstream_xchacha20poly1305_abytes()];
            let adlen: u64;
            let adptr: *const u8;
            let tag: u8 = tag.unwrap_or(MessageTag::Message).into();
            match ad {
                Some(ad) => {
                    adptr = ad.as_ptr();
                    adlen = ad.len() as u64
                }
                None => {
                    adptr = std::ptr::null::<u8>();
                    adlen = 0;
                }
            };
            _sodium::crypto_secretstream_xchacha20poly1305_push(
                self.state,
                ciphertext.as_mut_ptr(),
                std::ptr::null_mut::<u64>(),
                data.as_ptr(),
                data.len() as u64,
                adptr,
                adlen,
                tag,
            );
            Ok(ciphertext)
        }
    }

    pub fn pull(
        &self,
        ciphertext: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<(Vec<u8>, MessageTag), &'static str> {
        unsafe {
            if ciphertext.len() < _sodium::crypto_secretstream_xchacha20poly1305_abytes() {
                return Err("Ciphertext too short");
            }
            let mut plaintext = vec![
                0u8;
                ciphertext.len()
                    - _sodium::crypto_secretstream_xchacha20poly1305_abytes()
            ];
            let adlen: u64;
            let adptr: *const u8;
            let mut tag = 0u8;
            match ad {
                Some(ad) => {
                    adptr = ad.as_ptr();
                    adlen = ad.len() as u64
                }
                None => {
                    adptr = std::ptr::null::<u8>();
                    adlen = 0;
                }
            };
            match _sodium::crypto_secretstream_xchacha20poly1305_pull(
                self.state,
                plaintext.as_mut_ptr(),
                std::ptr::null_mut::<u64>(),
                &mut tag,
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                adptr,
                adlen,
            ) {
                0 => Ok((plaintext, MessageTag::try_from(tag)?)),
                _ => Err("Invalid ciphertext"),
            }
        }
    }
}

use super::_sodium;
use crate::sodium;
use crate::sodium::randombytes;
use crate::sodium::to_hex;
use byteorder::ByteOrder;
use failure::{ensure, err_msg, Error};
use std::ptr::{null, null_mut};

pub const ADDITIONAL_BYTES: usize = _sodium::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
pub const KEY_BYTES: usize = _sodium::crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;
pub const HEADER_BYTES: usize = _sodium::crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize - 8;

#[derive(PartialEq, Eq)]
pub enum Direction {
    Push,
    Pull,
}

pub struct SecretStream {
    header: Vec<u8>,
    key: Vec<u8>,
    counter: u64,
    dir: Direction,
}

pub fn generate_key() -> Vec<u8> {
    sodium::init().unwrap();
    unsafe {
        let mut key = vec![0u8; KEY_BYTES];
        _sodium::crypto_aead_xchacha20poly1305_ietf_keygen(key.as_mut_ptr());
        key
    }
}

impl SecretStream {
    pub fn get_header(&self) -> Vec<u8> {
        self.header.clone()
    }

    pub fn new_push(key: &[u8]) -> Result<SecretStream, Error> {
        sodium::init()?;
        ensure!(key.len() == KEY_BYTES, "Key length should be {}", KEY_BYTES);
        let header = randombytes(HEADER_BYTES);
        Ok(SecretStream {
            header,
            key: Vec::from(key),
            counter: 0,
            dir: Direction::Push,
        })
    }

    pub fn new_pull(header: &[u8], key: &[u8]) -> Result<SecretStream, Error> {
        sodium::init()?;
        ensure!(header.len() == HEADER_BYTES, "Header too short");
        ensure!(key.len() == KEY_BYTES, "Key length invalid");
        Ok(SecretStream {
            header: Vec::from(header),
            key: Vec::from(key),
            counter: 0,
            dir: Direction::Pull,
        })
    }

    pub fn push(&mut self, data: &[u8], ad: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        unsafe {
            ensure!(
                self.dir == Direction::Push,
                "Stream should be in push direction"
            );
            ensure!(
                data.len() <= _sodium::crypto_aead_xchacha20poly1305_ietf_messagebytes_max(),
                "Message too long"
            );
            let mut ciphertext = vec![0u8; data.len() + ADDITIONAL_BYTES];
            let (ad, adlen) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len() as u64),
                None => (std::ptr::null::<u8>(), 0),
            };
            let mut clen: u64 = 0;
            let mut nonce = vec![0u8; _sodium::crypto_aead_xchacha20poly1305_ietf_npubbytes()];
            nonce[0..HEADER_BYTES].copy_from_slice(&self.header);
            byteorder::BigEndian::write_u64(&mut nonce[HEADER_BYTES..], self.counter);
            println!("{:}", to_hex(&nonce));
            _sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext.as_mut_ptr(),
                &mut clen as *mut u64,
                data.as_ptr(),
                data.len() as u64,
                ad,
                adlen,
                null(),
                nonce.as_ptr(),
                self.key.as_ptr(),
            );
            ciphertext.truncate(clen as usize);
            self.counter += 1;
            Ok(ciphertext)
        }
    }

    pub fn pull(&mut self, ciphertext: &[u8], ad: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        unsafe {
            ensure!(
                self.dir == Direction::Pull,
                "Stream should be in pull direction"
            );
            ensure!(ciphertext.len() >= ADDITIONAL_BYTES, "Ciphertext too short");
            let mut plaintext = vec![0u8; ciphertext.len() - ADDITIONAL_BYTES];
            let (ad, adlen) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len() as u64),
                None => (std::ptr::null(), 0),
            };
            let mut nonce = vec![0u8; _sodium::crypto_aead_xchacha20poly1305_ietf_npubbytes()];
            nonce[0..HEADER_BYTES].copy_from_slice(&self.header);
            byteorder::BigEndian::write_u64(&mut nonce[HEADER_BYTES..], self.counter);
            let mut mlen: u64 = 0;
            match _sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext.as_mut_ptr(),
                &mut mlen as *mut u64,
                null_mut(),
                ciphertext.as_ptr(),
                ciphertext.len() as u64,
                ad,
                adlen,
                nonce.as_ptr(),
                self.key.as_ptr(),
            ) {
                0 => {
                    self.counter += 1;
                    Ok(plaintext)
                }
                _ => Err(err_msg("Invalid ciphertext")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sodium::secretstream;
    use crate::sodium::{init, randombytes};
    use std::time::Instant;

    fn stream_perf_test_size(size: usize) {
        let key = secretstream::generate_key();
        let mut pusher = secretstream::SecretStream::new_push(&key).unwrap();
        let mut puller = secretstream::SecretStream::new_pull(&pusher.get_header(), &key).unwrap();
        let input = randombytes(size);
        let iterations = 40000;
        let start = Instant::now();
        for i in 1..=iterations {
            let _ = pusher.push(&input, None);
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
        init().unwrap();
        for size in &[1024, 4096, 8192, 16384, 65536] {
            stream_perf_test_size(*size);
        }
    }

    #[test]
    #[should_panic]
    fn test_key_size() {
        let key = randombytes(69);
        secretstream::SecretStream::new_push(&key).unwrap();
    }

    #[test]
    fn stream_test() {
        let key = secretstream::generate_key();
        let mut pusher = secretstream::SecretStream::new_push(&key).unwrap();
        let mut puller = secretstream::SecretStream::new_pull(&pusher.get_header(), &key).unwrap();
        let input = randombytes(1024);
        for _ in 1..100 {
            let c = pusher.push(&input, None).unwrap();
            let p = puller.pull(&c, None).unwrap();
            assert_eq!(p, input);
        }
    }
}

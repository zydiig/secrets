use crate::sodium::_sodium;
use std::ptr::null;
use std::ptr::null_mut;

pub const ADDITIONAL_BYTES: usize = _sodium::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
pub const NONCE_BYTES: usize = _sodium::crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize;
pub const KEY_BYTES: usize = _sodium::crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;

pub fn encrypt(data: &[u8], key: &[u8], nonce: &[u8], ad: Option<&[u8]>) -> Vec<u8> {
    unsafe {
        let mut ciphertext = vec![0u8; data.len() + ADDITIONAL_BYTES];
        let (ad, ad_len) = match ad {
            Some(ad) => (ad.as_ptr(), ad.len()),
            None => (null(), 0),
        };
        let mut size: u64 = ciphertext.len() as u64;
        _sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.as_mut_ptr(),
            &mut size as *mut u64,
            data.as_ptr(),
            data.len() as u64,
            ad,
            ad_len as u64,
            null(),
            nonce.as_ptr(),
            key.as_ptr(),
        );
        ciphertext.truncate(size as usize);
        ciphertext
    }
}

pub fn decrypt(
    data: &[u8],
    key: &[u8],
    nonce: &[u8],
    ad: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    unsafe {
        if data.len() < ADDITIONAL_BYTES {
            return Err("Ciphertext too short");
        }
        let mut plaintext = vec![0u8; data.len() - ADDITIONAL_BYTES];
        let (ad, ad_len) = match ad {
            Some(ad) => (ad.as_ptr(), ad.len()),
            None => (null(), 0),
        };
        let mut size: u64 = plaintext.len() as u64;
        match _sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &mut size as *mut u64,
            null_mut(),
            data.as_ptr(),
            data.len() as u64,
            ad,
            ad_len as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        ) {
            0 => {
                plaintext.truncate(size as usize);
                Ok(plaintext)
            }
            _ => Err("Failed to decrypt"),
        }
    }
}

pub mod aes {
    use crate::sodium::_sodium;
    use std::ptr::{null, null_mut};

    pub const KEY_BYTES: usize = _sodium::crypto_aead_aes256gcm_KEYBYTES as usize;
    pub const ADDITIONAL_BYTES: usize = _sodium::crypto_aead_aes256gcm_ABYTES as usize;
    pub const NONCE_BYTES: usize = _sodium::crypto_aead_aes256gcm_NPUBBYTES as usize;

    pub fn encrypt(data: &[u8], key: &[u8], nonce: &[u8], ad: Option<&[u8]>) -> Vec<u8> {
        unsafe {
            let mut ciphertext = vec![0u8; data.len() + ADDITIONAL_BYTES];
            let (ad, ad_len) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len()),
                None => (null(), 0),
            };
            _sodium::crypto_aead_aes256gcm_encrypt(
                ciphertext.as_mut_ptr(),
                null_mut(),
                data.as_ptr(),
                data.len() as u64,
                ad,
                ad_len as u64,
                null(),
                nonce.as_ptr(),
                key.as_ptr(),
            );
            ciphertext
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sodium::aead::{aes, encrypt, KEY_BYTES, NONCE_BYTES};
    use crate::sodium::{init, randombytes};
    use std::time::Instant;

    const ITERATIONS: usize = 1024 * 16;

    fn aead_perf_test_size(size: usize) {
        let data = randombytes(size);
        let key = randombytes(KEY_BYTES);
        let nonce = randombytes(NONCE_BYTES);
        let start = Instant::now();
        for i in 1..=ITERATIONS {
            let result = encrypt(&data, &key, &nonce, None);
        }
        let time = Instant::now().duration_since(start).as_secs_f64();
        println!(
            "size={}, speed={}",
            size,
            (size * ITERATIONS) as f64 / time / 1024.0 / 1024.0
        );
    }

    fn aes_perf_test_size(size: usize) {
        let data = randombytes(size);
        let key = randombytes(aes::KEY_BYTES);
        let nonce = randombytes(aes::NONCE_BYTES);
        let start = Instant::now();
        for i in 1..=ITERATIONS {
            let result = aes::encrypt(&data, &key, &nonce, None);
        }
        let time = Instant::now().duration_since(start).as_secs_f64();
        println!(
            "AES: size={}, speed={}",
            size,
            (size * ITERATIONS) as f64 / time / 1024.0 / 1024.0
        );
    }

    #[test]
    fn aead_perf_test() {
        init().unwrap();
        for &size in &[128, 512, 1024, 2048, 4096, 8192, 16384, 65536] {
            aead_perf_test_size(size);
            aes_perf_test_size(size);
        }
    }
}

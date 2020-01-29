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

use super::_sodium;
use crate::utils::codecs;
use failure::ensure;
use serde::{Deserialize, Serialize};
use std::os::raw::c_ulonglong;

pub const MAC_BYTES: usize = _sodium::crypto_box_MACBYTES as usize;

pub const fn nonce_bytes() -> usize {
    _sodium::crypto_box_NONCEBYTES as usize
}

pub const fn public_key_bytes() -> usize {
    _sodium::crypto_box_PUBLICKEYBYTES as usize
}

pub const fn private_key_bytes() -> usize {
    _sodium::crypto_box_SECRETKEYBYTES as usize
}

pub const fn mac_bytes() -> usize {
    _sodium::crypto_box_MACBYTES as usize
}

#[derive(Serialize, Deserialize)]
pub struct Keypair {
    #[serde(
        serialize_with = "codecs::to_base64",
        deserialize_with = "codecs::from_base64"
    )]
    pub pk: Vec<u8>,
    #[serde(
        serialize_with = "codecs::to_base64",
        deserialize_with = "codecs::from_base64",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub sk: Vec<u8>,
}

impl Keypair {
    pub fn generate() -> Keypair {
        let mut pk = vec![0u8; public_key_bytes()];
        let mut sk = vec![0u8; private_key_bytes()];
        unsafe {
            _sodium::crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        Keypair { pk, sk }
    }
}

pub fn box_encrypt(data: &[u8], nonce: &[u8], public_key: &[u8], private_key: &[u8]) -> Vec<u8> {
    unsafe {
        let mut c = vec![0u8; data.len() + MAC_BYTES];
        _sodium::crypto_box_easy(
            c.as_mut_ptr(),
            data.as_ptr(),
            data.len() as u64,
            nonce.as_ptr(),
            public_key.as_ptr(),
            private_key.as_ptr(),
        );
        c
    }
}

pub fn box_decrypt(
    ciphertext: &[u8],
    nonce: &[u8],
    public_key: &[u8],
    private_key: &[u8],
) -> Result<Vec<u8>, &'static str> {
    unsafe {
        if ciphertext.len() < MAC_BYTES {
            return Err("Ciphertext too short");
        }
        let mut plaintext = vec![0u8; ciphertext.len() - MAC_BYTES];
        match _sodium::crypto_box_open_easy(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            public_key.as_ptr(),
            private_key.as_ptr(),
        ) {
            0 => Ok(plaintext),
            _ => Err("Invalid ciphertext"),
        }
    }
}

pub fn sealed_box_encrypt(m: &[u8], pk: &[u8]) -> Vec<u8> {
    unsafe {
        let mut result = vec![0u8; m.len() + _sodium::crypto_box_sealbytes()];
        _sodium::crypto_box_seal(
            result.as_mut_ptr(),
            m.as_ptr(),
            m.len() as c_ulonglong,
            pk.as_ptr(),
        );
        result
    }
}

pub fn sealed_box_decrypt(c: &[u8], pk: &[u8], sk: &[u8]) -> Result<Vec<u8>, failure::Error> {
    unsafe {
        ensure!(
            c.len() >= _sodium::crypto_box_sealbytes(),
            "Ciphertext too short"
        );
        let mut result = vec![0u8; c.len() - _sodium::crypto_box_sealbytes()];
        ensure!(
            _sodium::crypto_box_seal_open(
                result.as_mut_ptr(),
                c.as_ptr(),
                c.len() as c_ulonglong,
                pk.as_ptr(),
                sk.as_ptr(),
            ) == 0,
            "Invalid ciphertext"
        );
        Ok(result)
    }
}

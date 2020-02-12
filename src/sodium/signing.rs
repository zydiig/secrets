use super::_sodium;
use failure::{err_msg, Error};

pub const PUBLIC_KEY_BYTES: usize = _sodium::crypto_sign_PUBLICKEYBYTES as usize;
pub const SECRET_KEY_BYTES: usize = _sodium::crypto_sign_SECRETKEYBYTES as usize;
pub const SIG_BYTES: usize = _sodium::crypto_sign_BYTES as usize;

pub struct Keypair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut pk = vec![0u8; PUBLIC_KEY_BYTES];
        let mut sk = vec![0u8; SECRET_KEY_BYTES];
        unsafe {
            _sodium::crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        Self {
            public_key: pk,
            private_key: sk,
        }
    }
}

pub fn sign(data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Error> {
    if secret_key.len() != SECRET_KEY_BYTES {
        return Err(err_msg("Incorrect secret key length"));
    }
    let mut sm = vec![0u8; data.len() + SIG_BYTES];
    unsafe {
        _sodium::crypto_sign(
            sm.as_mut_ptr(),
            std::ptr::null_mut(),
            data.as_ptr(),
            data.len() as u64,
            secret_key.as_ptr(),
        );
    }
    Ok(sm)
}

pub fn open(signed_message: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Error> {
    if signed_message.len() < SIG_BYTES {
        return Err(err_msg("Signed message too short"));
    }
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(err_msg("Incorrect public key length"));
    }
    let mut m = vec![0u8; signed_message.len() - SIG_BYTES];
    unsafe {
        match _sodium::crypto_sign_open(
            m.as_mut_ptr(),
            std::ptr::null_mut(),
            signed_message.as_ptr(),
            signed_message.len() as u64,
            public_key.as_ptr(),
        ) {
            0 => Ok(m),
            _ => Err(err_msg("Signature verification failed")),
        }
    }
}

pub fn sign_detached(data: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, Error> {
    let mut sig = vec![0u8; SIG_BYTES];
    if secret_key.len() != SECRET_KEY_BYTES {
        return Err(err_msg("Incorrect secret key length"));
    }
    unsafe {
        _sodium::crypto_sign_detached(
            sig.as_mut_ptr(),
            std::ptr::null_mut(),
            data.as_ptr(),
            data.len() as u64,
            secret_key.as_ptr(),
        );
    }
    Ok(sig)
}

pub fn verify_detached(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, Error> {
    if public_key.len() != PUBLIC_KEY_BYTES {
        return Err(err_msg("Incorrect public key length"));
    }
    if signature.len() != SIG_BYTES {
        return Err(err_msg("Incorrect signature length"));
    }
    unsafe {
        Ok(_sodium::crypto_sign_verify_detached(
            signature.as_ptr(),
            data.as_ptr(),
            data.len() as u64,
            public_key.as_ptr(),
        ) == 0)
    }
}

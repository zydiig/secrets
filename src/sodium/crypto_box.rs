use super::_sodium;

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

pub struct Keypair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl Keypair {
    pub fn generate() -> Keypair {
        let mut pk = vec![0u8; public_key_bytes()];
        let mut sk = vec![0u8; private_key_bytes()];
        unsafe {
            _sodium::crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }
        Keypair {
            public_key: pk,
            private_key: sk,
        }
    }
}

pub fn seal_box(data: &[u8], nonce: &[u8], public_key: &[u8], private_key: &[u8]) -> Vec<u8> {
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

pub fn open_box(
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

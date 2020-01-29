use crate::sodium::_sodium;
use std::os::raw::c_char;

pub const KEY_BYTES: usize = _sodium::crypto_kdf_KEYBYTES as usize;

pub fn keygen() -> Vec<u8> {
    unsafe {
        let mut key = vec![0u8; KEY_BYTES];
        _sodium::crypto_kdf_keygen(key.as_mut_ptr());
        key
    }
}

pub fn derive(master_key: &[u8], subkey_len: usize, subkey_id: u64, context: &str) -> Vec<u8> {
    unsafe {
        let mut subkey = vec![0u8; subkey_len];
        _sodium::crypto_kdf_derive_from_key(
            subkey.as_mut_ptr(),
            subkey_len,
            subkey_id,
            context.as_ptr() as *const c_char,
            master_key.as_ptr(),
        );
        subkey
    }
}

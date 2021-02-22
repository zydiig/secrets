use crate::sodium::_sodium;
use failure::ensure;
use std::os::raw::c_ulonglong;

pub const MAC_BYTES: usize = _sodium::crypto_secretbox_MACBYTES as usize;
pub const NONCE_BYTES: usize = _sodium::crypto_secretbox_NONCEBYTES as usize;
pub const KEY_BYTES: usize = _sodium::crypto_secretbox_KEYBYTES as usize;

pub fn seal(m: &[u8], nonce: &[u8], key: &[u8]) -> Vec<u8> {
    assert_eq!(nonce.len(), _sodium::crypto_secretbox_NONCEBYTES as usize);
    assert_eq!(key.len(), _sodium::crypto_secretbox_KEYBYTES as usize);
    let mut result = vec![0u8; m.len() + _sodium::crypto_secretbox_MACBYTES as usize];
    unsafe {
        _sodium::crypto_secretbox_easy(
            result.as_mut_ptr(),
            m.as_ptr(),
            m.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        );
    }
    result
}

pub fn open(c: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>, failure::Error> {
    assert_eq!(nonce.len(), _sodium::crypto_secretbox_NONCEBYTES as usize);
    assert_eq!(key.len(), _sodium::crypto_secretbox_KEYBYTES as usize);
    assert!(c.len() >= _sodium::crypto_secretbox_MACBYTES as usize);
    let mut result = vec![0u8; c.len() - _sodium::crypto_secretbox_MACBYTES as usize];
    ensure!(
        unsafe {
            _sodium::crypto_secretbox_open_easy(
                result.as_mut_ptr(),
                c.as_ptr(),
                c.len() as c_ulonglong,
                nonce.as_ptr(),
                key.as_ptr(),
            )
        } == 0,
        "Error opening secretbox"
    );
    Ok(result)
}

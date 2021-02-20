use once_cell::sync::OnceCell;
use std::ffi::CStr;
use std::sync::Once;

#[allow(dead_code, non_upper_case_globals, non_camel_case_types)]
mod _sodium;
pub mod aead;
pub mod crypto_box;
pub mod hashing;
pub mod kdf;
pub mod pwhash;
pub mod secretstream;
#[allow(dead_code)]
pub mod signing;

static INITIALIZED: OnceCell<::std::os::raw::c_int> = OnceCell::new();

pub fn init() -> Result<(), failure::Error> {
    if *INITIALIZED.get_or_init(|| unsafe { _sodium::sodium_init() }) < 0 {
        Err(failure::err_msg("Failed to initialize libsodium"))
    } else {
        Ok(())
    }
}

pub fn randombytes(length: usize) -> Vec<u8> {
    unsafe {
        let mut buf = vec![0u8; length];
        _sodium::randombytes_buf(buf.as_mut_ptr() as *mut std::ffi::c_void, length);
        buf
    }
}

pub fn increment(n: &mut [u8]) {
    unsafe {
        _sodium::sodium_increment(n.as_mut_ptr(), n.len());
    }
}

pub fn to_hex(data: &[u8]) -> String {
    let mut result = vec![0u8; 2 * data.len() + 1];
    unsafe {
        _sodium::sodium_bin2hex(
            result.as_mut_ptr() as *mut i8,
            result.len(),
            data.as_ptr(),
            data.len(),
        );
        CStr::from_ptr(result.as_ptr() as *const i8)
            .to_str()
            .unwrap()
            .to_owned()
    }
}

#[cfg(test)]
mod tests {
    use crate::sodium::{increment, to_hex};

    #[test]
    fn to_hex_test() {
        let data = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12";
        assert_eq!(to_hex(data), "123456789abcdef012");
    }

    #[test]
    fn increment_test() {
        let mut data = b"\xff\xff\xff\x00".to_vec();
        increment(&mut data);
        assert_eq!(data.as_slice(), b"\x00\x00\x00\x01");
        increment(&mut data);
        assert_eq!(data.as_slice(), b"\x01\x00\x00\x01");
    }
}

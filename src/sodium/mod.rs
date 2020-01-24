#[allow(dead_code, non_upper_case_globals,non_camel_case_types)]
mod _sodium;
pub mod crypto_box;
pub mod hashing;
pub mod secretstream;
#[allow(dead_code)]
pub mod signing;

pub fn init() -> Result<(), &'static str> {
    unsafe {
        if _sodium::sodium_init() < 0 {
            return Err("Failed to initialize libsodium");
        }
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

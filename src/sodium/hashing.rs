use super::_sodium;
use std::alloc;
use std::mem;

type HashState = _sodium::crypto_generichash_state;

pub struct Hasher {
    state: *mut HashState,
}

impl Hasher {
    pub fn new() -> Self {
        unsafe {
            let state = alloc::alloc(
                alloc::Layout::from_size_align(
                    _sodium::crypto_generichash_STATEBYTES,
                    mem::align_of::<u8>(),
                )
                .expect("Bad memory layout"),
            ) as *mut HashState;
            _sodium::crypto_generichash_init(
                state,
                std::ptr::null(),
                0usize,
                _sodium::crypto_generichash_BYTES as usize,
            );
            Self { state }
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            _sodium::crypto_generichash_update(self.state, data.as_ptr(), data.len() as u64);
        }
    }
    pub fn finalize(&mut self) -> Vec<u8> {
        unsafe {
            let mut hash = vec![0u8; _sodium::crypto_generichash_BYTES as usize];
            _sodium::crypto_generichash_final(
                self.state,
                hash.as_mut_ptr(),
                _sodium::crypto_generichash_BYTES as usize,
            );
            hash
        }
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        unsafe {
            alloc::dealloc(
                self.state as *mut u8,
                alloc::Layout::from_size_align(
                    _sodium::crypto_generichash_STATEBYTES,
                    mem::align_of::<u8>(),
                )
                .expect("Bad memory layout"),
            );
        }
    }
}

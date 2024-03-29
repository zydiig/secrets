use crate::sodium::_sodium;
use failure::{err_msg, Error};

pub const SALT_BYTES: usize = _sodium::crypto_pwhash_SALTBYTES as usize;

pub fn pwhash(
    password: &str,
    outlen: usize,
    salt: &[u8],
    opslimit: u64,
    memlimit: usize,
) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; outlen];
    unsafe {
        match _sodium::crypto_pwhash(
            out.as_mut_ptr(),
            outlen as u64,
            password.as_ptr() as *const i8,
            password.len() as u64,
            salt.as_ptr(),
            opslimit,
            memlimit,
            _sodium::crypto_pwhash_ALG_ARGON2ID13 as i32,
        ) {
            0 => Ok(out),
            _ => Err(err_msg("Error deriving key from password")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sodium::pwhash::{pwhash, SALT_BYTES};
    use crate::sodium::randombytes;
    use crate::sodium::secretstream::KEY_BYTES;
    use std::time::Instant;

    #[test]
    fn pwhash_test() {
        let salt = randombytes(SALT_BYTES);
        let start = Instant::now();
        println!(
            "{:?}",
            pwhash("password", KEY_BYTES, &salt, 3, 1024 * 1024 * 1024).unwrap()
        );
        println!("{}", Instant::now().duration_since(start).as_secs_f64());
    }
}

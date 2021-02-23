mod ffi;
use crate::utils::codecs;
use failure::ensure;
use serde::{Deserialize, Serialize};

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

pub struct EncapsulationResult {
    pub ss: Vec<u8>,
    pub ct: Vec<u8>,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut keypair = Keypair {
            pk: vec![0u8; ffi::pqcrystals_kyber1024_ref_PUBLICKEYBYTES as usize],
            sk: vec![0u8; ffi::pqcrystals_kyber1024_ref_SECRETKEYBYTES as usize],
        };
        unsafe {
            assert_eq!(
                ffi::pqcrystals_kyber1024_ref_keypair(
                    keypair.pk.as_mut_ptr(),
                    keypair.sk.as_mut_ptr()
                ),
                0
            );
        }
        keypair
    }
}

pub fn encapsulate(pk: &[u8]) -> EncapsulationResult {
    let mut ss = vec![0u8; ffi::pqcrystals_kyber1024_ref_BYTES as usize];
    let mut ct = vec![0u8; ffi::pqcrystals_kyber1024_ref_CIPHERTEXTBYTES as usize];
    unsafe {
        ffi::pqcrystals_kyber1024_ref_enc(ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr());
    }
    EncapsulationResult { ss, ct }
}

pub fn decapsulate(ct: &[u8], sk: &[u8]) -> Vec<u8> {
    let mut ss = vec![0u8; ffi::pqcrystals_kyber1024_ref_BYTES as usize];
    unsafe {
        ffi::pqcrystals_kyber1024_ref_dec(ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr());
    }
    ss
}

#[cfg(test)]
mod tests {
    use crate::kyber::{decapsulate, encapsulate, Keypair};
    use crate::sodium::to_hex;

    #[test]
    fn keygen_test() {
        let keypair = Keypair::generate();
        println!("PK={}", base64::encode(&keypair.pk));
        println!("SK={}", base64::encode(&keypair.sk));
        for _ in 1..10 {
            let ret = encapsulate(&keypair.pk);
            let ss = decapsulate(&ret.ct, &keypair.sk);
            assert_eq!(ss, ret.ss);
            println!("SS={}", to_hex(&ss));
        }
    }
}

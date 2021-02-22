use crate::sodium::_sodium;
use failure::ensure;

pub struct Keypair {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
}

pub struct SessionKeys {
    pub rx: Vec<u8>,
    pub tx: Vec<u8>,
}

impl Keypair {
    pub fn generate() -> Self {
        unsafe {
            let mut keypair = Self {
                pk: vec![0u8; _sodium::crypto_kx_publickeybytes()],
                sk: vec![0u8; _sodium::crypto_kx_secretkeybytes()],
            };
            _sodium::crypto_kx_keypair(keypair.pk.as_mut_ptr(), keypair.sk.as_mut_ptr());
            keypair
        }
    }

    pub fn server_session_keys(&self, client_pk: &[u8]) -> Result<SessionKeys, failure::Error> {
        unsafe {
            let mut key = SessionKeys {
                rx: vec![0u8; _sodium::crypto_kx_sessionkeybytes()],
                tx: vec![0u8; _sodium::crypto_kx_sessionkeybytes()],
            };
            ensure!(
                _sodium::crypto_kx_server_session_keys(
                    key.rx.as_mut_ptr(),
                    key.tx.as_mut_ptr(),
                    self.pk.as_ptr(),
                    self.sk.as_ptr(),
                    client_pk.as_ptr(),
                ) == 0,
                "Invalid client public key"
            );
            Ok(key)
        }
    }

    pub fn client_session_keys(&self, server_pk: &[u8]) -> Result<SessionKeys, failure::Error> {
        unsafe {
            let mut key = SessionKeys {
                rx: vec![0u8; _sodium::crypto_kx_sessionkeybytes()],
                tx: vec![0u8; _sodium::crypto_kx_sessionkeybytes()],
            };
            ensure!(
                _sodium::crypto_kx_client_session_keys(
                    key.rx.as_mut_ptr(),
                    key.tx.as_mut_ptr(),
                    self.pk.as_ptr(),
                    self.sk.as_ptr(),
                    server_pk.as_ptr(),
                ) == 0,
                "Invalid client public key"
            );
            Ok(key)
        }
    }
}

use crate::kyber;
use crate::sodium;
use crate::sodium::crypto_box;
use crate::sodium::crypto_box::Keypair;
use crate::sodium::pwhash::pwhash;
use crate::sodium::randombytes;
use crate::utils::codecs;
use failure::{Fail, ResultExt};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct Key {
    box_keypair: crypto_box::Keypair,
    kyber_keypair: kyber::Keypair,
}

impl Key {
    pub fn load_from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, failure::Error> {
        let mut file = File::open(path.as_ref()).context("Error opening key file")?;
        let mut salt = vec![0u8; sodium::pwhash::SALT_BYTES];
        file.read_exact(&mut salt);
        let key = sodium::pwhash::pwhash(
            password,
            sodium::secretbox::KEY_BYTES,
            &salt,
            3,
            1024 * 1024 * 1024,
        )
        .context("Error deriving key from password")?;
        let mut nonce = vec![0u8; sodium::secretbox::NONCE_BYTES];
        file.read_exact(&mut nonce);
        let mut content = Vec::new();
        file.read_to_end(&mut content);
        let content =
            sodium::secretbox::open(&content, &nonce, &key).context("Error decrypting key")?;
        println!("{}", String::from_utf8_lossy(&content));
        let key: Key = serde_json::from_slice(&content).context("Error parsing key")?;
        return Ok(key);
    }

    pub fn generate() -> Result<Self, failure::Error> {
        let box_keypair = sodium::crypto_box::Keypair::generate();
        let kyber_keypair = kyber::Keypair::generate();
        Ok(Self {
            box_keypair,
            kyber_keypair,
        })
    }

    pub fn export_public_keys(&self) -> PublicKey {
        PublicKey {
            box_pk: self.box_keypair.pk.clone(),
            kyber_pk: self.kyber_keypair.pk.clone(),
        }
    }

    pub fn save_to_file<P: AsRef<Path>>(
        &self,
        path: P,
        password: &str,
    ) -> Result<(), failure::Error> {
        let mut file = File::create(path.as_ref()).context("Error creating key file")?;
        let salt = randombytes(sodium::pwhash::SALT_BYTES);
        file.write_all(&salt)
            .context("Error writing salt to key file")?;
        let nonce = randombytes(sodium::secretbox::NONCE_BYTES);
        file.write_all(&nonce)
            .context("Error writing nonce to key file")?;
        let key = pwhash(
            password,
            sodium::secretbox::KEY_BYTES,
            &salt,
            3,
            1024 * 1024 * 1024,
        )
        .context("Error deriving key from password")?;
        let content = sodium::secretbox::seal(
            &serde_json::to_vec(self).context("Error serializing key")?,
            &nonce,
            &key,
        );
        file.write_all(&content);
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(
        serialize_with = "codecs::to_base64",
        deserialize_with = "codecs::from_base64"
    )]
    pub box_pk: Vec<u8>,
    #[serde(
        serialize_with = "codecs::to_base64",
        deserialize_with = "codecs::from_base64"
    )]
    pub kyber_pk: Vec<u8>,
}

impl PublicKey {
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), failure::Error> {
        let mut file = File::create(path.as_ref()).context("Error opening file for write")?;
        file.write_all(&serde_json::to_vec_pretty(self).context("Error serializing public key")?)
            .context("Error writing public key")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::key::Key;
    use crate::sodium;

    #[test]
    fn keygen_test() {
        sodium::init().unwrap();
        let keypair = Key::generate().unwrap();
        keypair.save_to_file("/tmp/test.key", "password");
        keypair.export_public_keys().save_to_file("/tmp/test.pub");
        Key::load_from_file("/tmp/test.key", "password");
    }
}

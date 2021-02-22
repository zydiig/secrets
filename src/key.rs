use crate::kyber;
use crate::sodium;
use crate::sodium::pwhash::pwhash;
use crate::sodium::randombytes;
use failure::{Fail, ResultExt};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct FullKey {
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    x25519_pk: Vec<u8>,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    x25519_sk: Vec<u8>,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    kyber_pk: Vec<u8>,
    #[serde(serialize_with = "to_base64", deserialize_with = "from_base64")]
    kyber_sk: Vec<u8>,
}

fn to_base64<S>(key: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(&key))
}

fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(|err| D::Error::custom(err.to_string())))
}

impl FullKey {
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
        let key: FullKey = serde_json::from_slice(&content).context("Error parsing key")?;
        return Ok(key);
    }

    pub fn generate() -> Result<Self, failure::Error> {
        let x25519_keypair = sodium::kx::Keypair::generate();
        let kyber_keypair = kyber::Keypair::generate();
        Ok(Self {
            x25519_pk: x25519_keypair.pk,
            x25519_sk: x25519_keypair.sk,
            kyber_pk: kyber_keypair.pk,
            kyber_sk: kyber_keypair.sk,
        })
    }

    pub fn save_to_file<P: AsRef<Path>>(
        &mut self,
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

pub struct PublicKey {
    x25519_pk: Vec<u8>,
    kyber_pk: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use crate::key::FullKey;
    use crate::sodium;

    #[test]
    fn keygen_test() {
        sodium::init().unwrap();
        FullKey::generate()
            .unwrap()
            .save_to_file("/tmp/test.key", "password");
        FullKey::load_from_file("/tmp/test.key", "password");
    }
}

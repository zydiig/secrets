use crate::encoding::Base64Data;
use crate::errors;
use crate::sodium::{crypto_box, signing};
use errors::Error;
use serde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs::File;
use std::io::prelude::*;

#[derive(PartialEq, Eq)]
pub enum KeyType {
    FullKey,
    PublicKey,
}
impl Serialize for KeyType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match *self {
            KeyType::PublicKey => "public",
            KeyType::FullKey => "full",
        })
    }
}

impl<'de> Deserialize<'de> for KeyType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| match string.as_str() {
            "public" => Ok(KeyType::PublicKey),
            "full" => Ok(KeyType::FullKey),
            _ => Err(Error::custom("Not a valid key type")),
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct Key {
    pub key_type: KeyType,
    pub enc_pk: Base64Data,
    pub enc_sk: Option<Base64Data>,
    pub sig_pk: Base64Data,
    pub sig_sk: Option<Base64Data>,
}

impl Key {
    pub fn export_public(&self) -> Self {
        Self {
            key_type: KeyType::PublicKey,
            enc_pk: self.enc_pk.clone(),
            enc_sk: None,
            sig_pk: self.sig_pk.clone(),
            sig_sk: None,
        }
    }
}

fn create_file(path: &std::path::Path) -> errors::Result<File> {
    std::fs::create_dir_all(
        path.parent()
            .ok_or_else(|| Error::new("Error creating directories"))?,
    )?;
    Ok(File::create(path)?)
}

pub fn generate_key(name: Option<&str>) -> errors::Result<()> {
    let name = name.unwrap_or("key");
    let path = dirs::home_dir()
        .unwrap()
        .join(".secrets")
        .join(format!("{}.key", name));
    let mut key_file = create_file(&path)?;
    let enc_keypair = crypto_box::Keypair::generate();
    let sig_keypair = signing::Keypair::generate();
    let key = Key {
        key_type: KeyType::FullKey,
        enc_pk: Base64Data(enc_keypair.public_key),
        enc_sk: Some(Base64Data(enc_keypair.private_key)),
        sig_pk: Base64Data(sig_keypair.public_key),
        sig_sk: Some(Base64Data(sig_keypair.private_key)),
    };
    let out = serde_json::to_string_pretty(&key)?;
    key_file.write_all(&out.as_bytes())?;
    Ok(())
}

pub fn read_key(name: Option<&str>, key_type: KeyType) -> errors::Result<Key> {
    let name = name.unwrap_or("key");
    let mut path = dirs::home_dir().unwrap().join(".secrets");
    match key_type {
        KeyType::FullKey => path = path.join(format!("{}.key", name)),
        KeyType::PublicKey => path = path.join(format!("{}.pub", name)),
    };
    let mut key_file = match File::open(path) {
        Ok(f) => f,
        Err(_) if key_type == KeyType::PublicKey => return read_key(Some(name), KeyType::FullKey),
        Err(e) => return Err(From::from(e)),
    };
    let mut key = String::new();
    key_file.read_to_string(&mut key)?;
    let key: Key = serde_json::from_str(&key)?;
    Ok(key)
}

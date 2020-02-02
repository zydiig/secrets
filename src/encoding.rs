use crate::sodium;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub struct Base64Data(pub Vec<u8>);

impl Serialize for Base64Data {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Data {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer)
            .and_then(|string| base64::decode(&string).map(Self).map_err(Error::custom))
    }
}

pub fn to_hex<T: AsRef<[u8]>>(data: T) -> String {
    sodium::to_hex(data.as_ref())
}

impl Base64Data {
    pub fn to_vec(&self) -> &Vec<u8> {
        AsRef::<Vec<u8>>::as_ref(self)
    }

    pub fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl AsRef<Vec<u8>> for Base64Data {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl AsRef<[u8]> for Base64Data {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

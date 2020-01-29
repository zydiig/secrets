use serde;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::io;
use std::path::Path;

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum ObjectType {
    File,
    Directory,
}

impl Serialize for ObjectType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match *self {
            ObjectType::Directory => "directory",
            ObjectType::File => "file",
        })
    }
}

impl<'de> Deserialize<'de> for ObjectType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        String::deserialize(deserializer).and_then(|string| match string.as_str() {
            "directory" => Ok(ObjectType::Directory),
            "file" => Ok(ObjectType::File),
            _ => Err(Error::custom("Not a valid object type")),
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ObjectInfo {
    pub object_type: ObjectType,
    pub name: String,
    pub original_path: String,
    pub path: Vec<String>,
    pub offset: Option<u64>,
    #[serde(skip)]
    pub epilogue: Option<ObjectEpilogue>,
}

impl Clone for ObjectInfo {
    fn clone(&self) -> Self {
        Self {
            object_type: self.object_type,
            name: self.name.clone(),
            original_path: self.original_path.clone(),
            path: self.path.clone(),
            epilogue: self.epilogue.clone(),
            offset: self.offset,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ObjectEpilogue {
    pub size: u64,
    pub hash: String,
}

impl ObjectInfo {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let metadata = std::fs::metadata(&path)?;
        let real_path = std::fs::canonicalize(&path)?;
        let name = real_path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Error getting filename"))?;
        let original_path = real_path
            .to_str()
            .map(|s| s.to_owned())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Error getting file path"))?;
        let object_path = real_path
            .components()
            .map(|s| s.as_os_str().to_str().unwrap().to_owned())
            .collect();
        if metadata.is_dir() {
            Ok(Self {
                object_type: ObjectType::Directory,
                name,
                original_path,
                path: object_path,
                epilogue: None,
                offset: None,
            })
        } else if metadata.is_file() {
            Ok(Self {
                object_type: ObjectType::File,
                name,
                original_path,
                path: object_path,
                epilogue: None,
                offset: None,
            })
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Unexpected object type",
            ))
        }
    }
}

use crate::sodium::hashing;
use serde_json::ser::State::Empty;
use std::fs;
use std::io;
use std::io::prelude::Write;
use std::io::Error;
use std::path::{Path, PathBuf};

pub fn generate_tree<P: AsRef<Path>>(path: P) -> io::Result<Vec<PathBuf>> {
    let path = path.as_ref();
    let mut result = Vec::new();
    result.push(path.to_path_buf());
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                result.extend(generate_tree(entry.path())?);
            } else {
                result.push(entry.path());
            }
        }
    }
    Ok(result)
}

pub struct EmptyWriter {}

impl Write for EmptyWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

pub struct HashingWriter<W: Write> {
    inner: Option<W>,
    hasher: hashing::Hasher,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: Some(writer),
            hasher: hashing::Hasher::new(),
        }
    }

    pub fn get_hash(&mut self) -> Vec<u8> {
        self.hasher.finalize()
    }

    pub fn into_inner(self) -> W {
        self.inner.unwrap()
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self.inner.as_mut() {
            Some(inner) => inner.write(buf).and_then(|count| {
                self.hasher.update(&buf[0..count]);
                Ok(count)
            }),
            None => {
                self.hasher.update(buf);
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        if let Some(inner) = self.inner.as_mut() {
            inner.flush()?;
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::generate_tree;

    #[test]
    fn exploration() {
        for p in generate_tree("/home/zhenyan/git/spdlog").unwrap().iter() {
            println!("{:?}", p);
        }
    }
}

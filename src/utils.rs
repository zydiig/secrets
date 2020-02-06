use crate::sodium::hashing;
use std::fs;
use std::io;
use std::io::prelude::Write;
use std::io::Error;
use std::path::{Path, PathBuf};

pub fn generate_tree<P: AsRef<Path>>(path: P, follow_symlinks: bool) -> io::Result<Vec<PathBuf>> {
    let path = path.as_ref();
    let mut result = Vec::new();
    result.push(path.to_path_buf());
    let metadata = match follow_symlinks {
        true => fs::metadata(path)?,
        false => fs::symlink_metadata(path)?,
    };
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            result.extend(generate_tree(entry.path(), follow_symlinks)?);
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
    fn tree_test() {
        for p in generate_tree("/home/zhenyan/git/spdlog", true)
            .unwrap()
            .iter()
        {
            println!("{:?}", p);
        }
    }

    #[test]
    fn symlink_test() {
        let l = generate_tree("/tmp/td/", true).unwrap();
        l.iter().for_each(|item| println!("{:?}", item));
    }
}

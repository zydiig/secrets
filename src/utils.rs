use crate::sodium::hashing;
use failure::{err_msg, Error, ResultExt};
use regex::Regex;
use std::fs;
use std::io;
use std::io::prelude::Write;
use std::path::{Path, PathBuf};

pub fn parse_size(size: &str) -> Result<u64, Error> {
    let pattern: Regex = Regex::new("^([0-9.]+)(K|M|G)?$").unwrap();
    let capture = pattern
        .captures(size)
        .ok_or_else(|| err_msg("Invalid size specification"))?;
    let mut base: f64 = capture[1].parse::<f64>().context("Error parsing number")?;
    base *= match capture.get(2).map(|s| s.as_str()) {
        Some("K") => 1024,
        Some("M") => 1024 * 1024,
        Some("G") => 1024 * 1024 * 1024,
        _ => 1,
    } as f64;
    Ok(base.floor() as u64)
}

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
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
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
    use crate::utils::{generate_tree, parse_size};

    #[test]
    fn size_test() {
        assert_eq!(parse_size("16G").unwrap(), 16 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("4G").unwrap(), 4 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size("128K").unwrap(), 128 * 1024);
    }

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

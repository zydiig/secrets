use std::cmp::{max, min};
use std::io;

use crate::encoding::to_hex;

pub struct Buffer {
    buf: Vec<u8>,
    offset: usize,
    len: usize,
}

impl Buffer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity],
            offset: 0,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        return &self.buf[self.offset..self.offset + self.len];
    }

    pub fn put(&mut self, buf: &[u8]) {
        let mut capacity = self.buf.len() - (self.offset + self.len);
        if buf.len() > capacity {
            self.buf.copy_within(self.offset..self.offset + self.len, 0);
            capacity += self.offset;
            self.offset = 0;
        }
        if buf.len() > capacity {
            self.buf.reserve(buf.len() - capacity);
            self.buf.resize(self.buf.len(), 0);
        }
        self.buf[self.offset + self.len..self.offset + self.len + buf.len()].copy_from_slice(buf);
        self.len += buf.len();
    }

    pub fn drain_into(&mut self, buf: &mut [u8]) -> usize {
        let size = min(buf.len(), self.len);
        buf[0..size].copy_from_slice(&self.buf[self.offset..self.offset + size]);
        self.offset += size;
        self.len -= size;
        size
    }
}

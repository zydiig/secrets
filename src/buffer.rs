use std::cmp::min;

use std::borrow::Borrow;
use std::ops::{Bound, Deref, DerefMut, Index, IndexMut, RangeBounds};
use std::slice::SliceIndex;

pub struct Buffer {
    buf: Vec<u8>,
    offset: usize,
    len: usize,
    initial_capacity: usize,
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.offset..self.offset + self.len]
    }
}

impl Borrow<[u8]> for Buffer {
    fn borrow(&self) -> &[u8] {
        &self.buf[self.offset..self.offset + self.len]
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[self.offset..self.offset + self.len]
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf[self.offset..self.offset + self.len]
    }
}

impl<I> Index<I> for Buffer
where
    I: SliceIndex<[u8], Output = [u8]>,
{
    type Output = [u8];

    fn index(&self, index: I) -> &Self::Output {
        &self.deref()[index]
    }
}

impl<I> IndexMut<I> for Buffer
where
    I: SliceIndex<[u8], Output = [u8]>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.deref_mut()[index]
    }
}

impl Buffer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity],
            offset: 0,
            len: 0,
            initial_capacity: capacity,
        }
    }

    pub fn wrap<R: RangeBounds<usize>>(vec: Vec<u8>, range: R) -> Self {
        let offset = match range.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(&i) => i,
            Bound::Excluded(&i) => i + 1,
        };
        let len = match range.end_bound() {
            Bound::Unbounded => vec.len() - offset,
            Bound::Included(&i) => i - offset,
            Bound::Excluded(&i) => i - offset - 1,
        };
        let size = vec.len();
        Self {
            buf: vec,
            offset,
            len,
            initial_capacity: size,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&mut self) -> &[u8] {
        let slice = &self.buf[self.offset..self.offset + self.len];
        self.offset = 0;
        self.len = 0;
        slice
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
            self.buf.resize(self.buf.capacity(), 0);
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

    pub fn to_vec(&self) -> Vec<u8> {
        self.buf[self.offset..self.offset + self.len].to_vec()
    }
}

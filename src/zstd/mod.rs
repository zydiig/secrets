use std::cmp::min;
use std::fs::read;
use std::io;
use std::io::prelude::*;
use std::os::raw::c_void;
use std::panic::resume_unwind;

use crate::buffer;
use crate::buffer::Buffer;

#[allow(
    dead_code,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
mod _zstd;

fn try_to(code: usize) -> Result<usize, io::Error> {
    unsafe {
        match _zstd::ZSTD_isError(code) {
            0 => Ok(code),
            _ => Err(io::Error::new(
                io::ErrorKind::Other,
                std::ffi::CStr::from_ptr(_zstd::ZSTD_getErrorName(code))
                    .to_str()
                    .expect("bad zstd error code"),
            )),
        }
    }
}

pub struct Compressor<W: Write> {
    ctx: *mut _zstd::ZSTD_CCtx,
    writer: Option<W>,
    output_buf: Vec<u8>,
}

pub struct Decompressor<R: Read> {
    ctx: *mut _zstd::ZSTD_DCtx,
    reader: Option<R>,
    output_buf: Vec<u8>,
    buf: buffer::Buffer,
    frame_ended: bool,
}

impl<W: Write> Compressor<W> {
    pub fn new(w: W, compression_level: i32) -> Self {
        unsafe {
            let result = Self {
                ctx: _zstd::ZSTD_createCCtx(),
                writer: Some(w),
                output_buf: vec![0u8; _zstd::ZSTD_CStreamOutSize()],
            };
            _zstd::ZSTD_CCtx_setParameter(
                result.ctx,
                _zstd::ZSTD_cParameter_ZSTD_c_compressionLevel,
                compression_level,
            );
            _zstd::ZSTD_CCtx_setParameter(
                result.ctx,
                _zstd::ZSTD_cParameter_ZSTD_c_checksumFlag,
                1,
            );
            result
        }
    }

    pub fn finish(&mut self) -> io::Result<()> {
        unsafe {
            let mut output = _zstd::ZSTD_outBuffer {
                dst: self.output_buf.as_mut_ptr() as *mut c_void,
                pos: 0,
                size: self.output_buf.len(),
            };
            loop {
                let ret = try_to(_zstd::ZSTD_endStream(
                    self.ctx,
                    &mut output as *mut _zstd::ZSTD_outBuffer,
                ))?;
                self.writer
                    .as_mut()
                    .unwrap()
                    .write_all(&self.output_buf[0..output.pos])?;
                if ret == 0 {
                    break;
                }
                output.pos = 0;
            }
        }
        Ok(())
    }
}

impl<W: Write> Write for Compressor<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        unsafe {
            let mut input = _zstd::ZSTD_inBuffer {
                src: buf.as_ptr() as *const c_void,
                pos: 0,
                size: buf.len(),
            };
            let mut output = _zstd::ZSTD_outBuffer {
                dst: self.output_buf.as_mut_ptr() as *mut c_void,
                pos: 0,
                size: self.output_buf.len(),
            };
            while input.pos < input.size {
                try_to(_zstd::ZSTD_compressStream(
                    self.ctx,
                    &mut output as *mut _zstd::ZSTD_outBuffer,
                    &mut input as *mut _zstd::ZSTD_inBuffer,
                ))?;
                self.writer
                    .as_mut()
                    .unwrap()
                    .write_all(&self.output_buf[0..output.pos])?;
                output.pos = 0;
            }
            Ok(input.pos)
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        unsafe {
            let mut output = _zstd::ZSTD_outBuffer {
                dst: self.output_buf.as_mut_ptr() as *mut c_void,
                pos: 0,
                size: self.output_buf.len(),
            };
            loop {
                let ret = try_to(_zstd::ZSTD_flushStream(
                    self.ctx,
                    &mut output as *mut _zstd::ZSTD_outBuffer,
                ))?;
                self.writer
                    .as_mut()
                    .unwrap()
                    .write_all(&self.output_buf[0..output.pos])?;
                if ret == 0 {
                    break;
                }
                output.pos = 0;
            }
        }
        Ok(())
    }
}

impl<W: Write> Drop for Compressor<W> {
    fn drop(&mut self) {
        self.finish().unwrap();
        unsafe {
            _zstd::ZSTD_freeCCtx(self.ctx);
        }
    }
}

impl<R: Read> Decompressor<R> {
    pub fn new(reader: R) -> Self {
        unsafe {
            Self {
                ctx: _zstd::ZSTD_createDCtx(),
                reader: Some(reader),
                output_buf: vec![0u8; _zstd::ZSTD_DStreamInSize()],
                buf: Buffer::with_capacity(4 * 1024 * 1024),
                frame_ended: false,
            }
        }
    }
}

impl<R: Read> Read for Decompressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.buf.is_empty() {
            return Ok(self.buf.drain_into(buf));
        } else if self.frame_ended {
            return Ok(0);
        }
        let mut cdata = vec![0u8; unsafe { _zstd::ZSTD_DStreamInSize() }];
        let count = self.reader.as_mut().unwrap().read(&mut cdata)?;
        unsafe {
            let mut input = _zstd::ZSTD_inBuffer {
                src: cdata.as_ptr() as *const c_void,
                pos: 0,
                size: count,
            };
            let mut output = _zstd::ZSTD_outBuffer {
                dst: self.output_buf.as_mut_ptr() as *mut c_void,
                pos: 0,
                size: self.output_buf.len(),
            };
            let mut ret: Option<usize> = None;
            while input.pos < input.size {
                ret = Some(try_to(_zstd::ZSTD_decompressStream(
                    self.ctx,
                    &mut output as *mut _zstd::ZSTD_outBuffer,
                    &mut input as *mut _zstd::ZSTD_inBuffer,
                ))?);
                self.buf.put(&self.output_buf[0..output.pos]);
                output.pos = 0;
            }
            if let Some(0) = ret {
                self.frame_ended = true;
            }
            Ok(self.buf.drain_into(buf))
        }
    }
}

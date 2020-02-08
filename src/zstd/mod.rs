use std::os::raw::c_void;

use crate::buffer;
use crate::buffer::Buffer;
use failure::{err_msg, format_err, Error};

#[allow(
    dead_code,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
mod _zstd;

fn try_to(code: usize) -> Result<usize, Error> {
    unsafe {
        match _zstd::ZSTD_isError(code) {
            0 => Ok(code),
            _ => Err(format_err!(
                "ZSTD error: {}",
                std::ffi::CStr::from_ptr(_zstd::ZSTD_getErrorName(code))
                    .to_str()
                    .expect("Bad zstd error code")
            )),
        }
    }
}

pub struct Compressor {
    ctx: *mut _zstd::ZSTD_CCtx,
    output_buf: Vec<u8>,
    buf: buffer::Buffer,
}

pub struct Decompressor {
    ctx: *mut _zstd::ZSTD_DCtx,
    output_buf: Vec<u8>,
    buf: buffer::Buffer,
    frame_ended: bool,
}

impl Compressor {
    pub fn new(compression_level: i32) -> Self {
        unsafe {
            let result = Self {
                ctx: _zstd::ZSTD_createCCtx(),
                output_buf: vec![0u8; _zstd::ZSTD_CStreamOutSize()],
                buf: Buffer::with_capacity(_zstd::ZSTD_CStreamOutSize() * 2),
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

    pub fn finish(&mut self) -> Result<&[u8], Error> {
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
                self.buf.put(&self.output_buf[0..output.pos]);
                if ret == 0 {
                    break;
                }
                output.pos = 0;
            }
            Ok(self.buf.as_slice())
        }
    }
    pub fn compress(&mut self, buf: &[u8]) -> Result<&[u8], Error> {
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
                self.buf.put(&self.output_buf[0..output.pos]);
                output.pos = 0;
            }
            Ok(self.buf.as_slice())
        }
    }
    fn flush(&mut self) -> Result<&[u8], Error> {
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
                self.buf.put(&self.output_buf[0..output.pos]);
                if ret == 0 {
                    break;
                }
                output.pos = 0;
            }
        }
        Ok(self.buf.as_slice())
    }
}

impl Drop for Compressor {
    fn drop(&mut self) {
        unsafe {
            _zstd::ZSTD_freeCCtx(self.ctx);
        }
    }
}

impl Decompressor {
    pub fn new() -> Self {
        unsafe {
            Self {
                ctx: _zstd::ZSTD_createDCtx(),
                output_buf: vec![0u8; _zstd::ZSTD_DStreamInSize()],
                buf: Buffer::with_capacity(4 * 1024 * 1024),
                frame_ended: false,
            }
        }
    }

    pub fn decompress(&mut self, buf: &[u8]) -> Result<&[u8], Error> {
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
            Ok(self.buf.as_slice())
        }
    }
}

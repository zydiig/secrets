extern crate secrets;

use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::mem::size_of;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use failure::{err_msg, Error, ResultExt};
use serde::{Deserialize, Serialize};

use secrets::{parsing, sodium, utils};

#[derive(Serialize, Deserialize)]
struct Epilogue {
    pub hash: String,
    pub size: u64,
}

fn write_chunk(
    stream: &mut sodium::secretstream::SecretStream,
    output: &mut dyn Write,
    data: &[u8],
    chunk_type: u8,
) -> Result<(), Error> {
    let mut info = vec![0u8; size_of::<u32>() + 1];
    BigEndian::write_u32(
        &mut info[1..],
        (data.len() + sodium::secretstream::ADDITIONAL_BYTES) as u32,
    );
    info[0] = chunk_type;
    let enc_info = stream.push(&info, None, None).unwrap();
    output
        .write_all(&enc_info)
        .context("Error writing chunk info")?;
    let enc_data = stream.push(data, None, None).unwrap();
    output
        .write_all(&enc_data)
        .context("Error writing chunk data")?;
    Ok(())
}

fn encrypt_file(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    password: &str,
) -> Result<Epilogue, Error> {
    let salt = sodium::randombytes(sodium::pwhash::SALT_BYTES);
    let opslimit = 3;
    let memlimit = 1 * 1024 * 1024; // 1GB
    let key = sodium::pwhash::pwhash(
        password,
        sodium::secretstream::KEY_BYTES,
        &salt,
        opslimit,
        memlimit,
    )
    .context("Error deriving key from password")?;
    let mut stream = sodium::secretstream::SecretStream::new_push(&key).unwrap();
    output.write_all(&salt).context("Error writing salt")?;
    output.write_u64::<BigEndian>(opslimit)?;
    output.write_u64::<BigEndian>(memlimit as u64)?;
    output.write_all(&stream.get_header())?;
    let mut hasher = sodium::hashing::Hasher::new();
    let mut buf = vec![0u8; 1024 * 256];
    let mut size = 0u64;
    loop {
        let count = input.read(&mut buf).context("Error reading from input")?;
        if count == 0 {
            break;
        }
        write_chunk(&mut stream, output, &buf[0..count], 0).context("Error writing data chunk")?;
        hasher.update(&buf[0..count]);
        size += count as u64;
    }
    let epilogue = Epilogue {
        hash: sodium::to_hex(hasher.finalize().as_slice()),
        size,
    };
    write_chunk(&mut stream, output, &serde_json::to_vec(&epilogue)?, 1)
        .context("Error writing epilogue")?;
    Ok(epilogue)
}

fn read_chunk(
    stream: &mut sodium::secretstream::SecretStream,
    input: &mut dyn BufRead,
) -> Result<(Vec<u8>, u8), Error> {
    let mut enc_info = vec![0u8; size_of::<u32>() + 1 + sodium::secretstream::ADDITIONAL_BYTES];
    input.read_exact(&mut enc_info)?;
    let info = stream.pull(&enc_info, None)?.0;
    let chunk_type = info[0];
    let size = BigEndian::read_u32(&info[1..]);
    let mut enc_data = vec![0u8; size as usize];
    input.read_exact(&mut enc_data)?;
    let data = stream.pull(&enc_data, None)?.0;
    Ok((data, chunk_type))
}

fn decrypt_file(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    password: &str,
) -> Result<Epilogue, Error> {
    let mut salt = vec![0u8; sodium::pwhash::SALT_BYTES];
    input.read_exact(&mut salt)?;
    let opslimit = input.read_u64::<BigEndian>()?;
    let memlimit = input.read_u64::<BigEndian>()? as usize;
    let key = sodium::pwhash::pwhash(
        password,
        sodium::secretstream::KEY_BYTES,
        &salt,
        opslimit,
        memlimit,
    )
    .context("Error deriving key from password")?;
    let mut header = vec![0u8; sodium::secretstream::HEADER_BYTES];
    input.read_exact(&mut header)?;
    let mut stream = sodium::secretstream::SecretStream::new_pull(&header, &key).unwrap();
    let mut hasher = sodium::hashing::Hasher::new();
    let mut epilogue: Option<Epilogue> = None;
    loop {
        let (chunk, chunk_type) = read_chunk(&mut stream, input)?;
        if chunk_type == 1 {
            epilogue = Some(serde_json::from_slice(&chunk)?);
            break;
        }
        output.write_all(&chunk)?;
        hasher.update(&chunk);
    }
    if sodium::to_hex(&hasher.finalize()) != epilogue.as_ref().unwrap().hash {
        panic!("Hash mismatch");
    }
    Ok(epilogue.unwrap())
}

fn main() {
    let args_vec: Vec<String> = env::args().collect();
    sodium::init().unwrap();
    let mut parser = parsing::Parser::new();
    parser.add_argument("encrypt", Some("e"), 0);
    parser.add_argument("decrypt", Some("d"), 0);
    parser.add_argument("input", Some("i"), 1);
    parser.add_argument("output", Some("o"), 1);
    parser.add_argument("passfile", Some("P"), 1);
    parser.add_argument("password", Some("p"), 1);
    let args = parser.parse_args(&args_vec[1..]).unwrap();
    if args.flags.contains_key("encrypt") && args.flags.contains_key("decrypt") {
        panic!("Invalid operation");
    }
    let mut input: Box<dyn BufRead> = match args.flags["input"].as_ref().unwrap().as_str() {
        "-" => Box::new(BufReader::new(io::stdin())),
        path @ _ => Box::new(BufReader::new(File::open(path).unwrap())),
    };
    let mut output: Box<dyn Write> = match args.flags["output"].as_ref().unwrap().as_str() {
        "-" => Box::new(io::stdout()),
        path @ _ => Box::new(File::create(path).unwrap()),
    };
    let password = utils::get_password(&args).unwrap();
    if args.flags.contains_key("encrypt") {
        encrypt_file(input.as_mut(), output.as_mut(), &password).unwrap();
    } else if args.flags.contains_key("decrypt") {
        decrypt_file(input.as_mut(), output.as_mut(), &password).unwrap();
    }
    output.as_mut().flush().unwrap();
}

extern crate byteorder;
extern crate dirs;
extern crate serde;
extern crate serde_json;
extern crate strum;
#[macro_use]
extern crate strum_macros;

use std::fs;
use std::fs::{read, File};
use std::io::prelude::*;
use std::io::BufReader;
use std::{env, io};

use serde_json::to_string_pretty;

use errors::Error;
use keys::{generate_key, read_key, KeyType};
use sodium::{hashing, signing};

use std::path::Path;

use crate::archive::{ArchiveReader, ObjectReader};
use crate::encoding::to_hex;
use crate::utils::EmptyWriter;
use archive::object::ObjectType;

#[macro_use]
mod errors;
mod archive;
mod buffer;
mod encoding;
mod keys;
mod parsing;
mod sodium;
mod utils;
mod zstd;

const CHUNK_SIZE: usize = 4 * 1024 * 1024;

fn get_path_components<P: AsRef<Path>>(path: P) -> Option<Vec<String>> {
    let mut result = Vec::new();
    for component in path.as_ref().components() {
        let s = component.as_os_str().to_str()?;
        result.push(s.to_owned());
    }
    Some(result)
}

fn encrypt_file(
    input_paths: &[String],
    output_path: &str,
    sender: Option<&str>,
    receiver: Option<&str>,
    compression_level: Option<i32>,
) -> errors::Result<()> {
    let sender_key = read_key(sender, KeyType::FullKey)?;
    let receiver_key = read_key(receiver, KeyType::PublicKey)?;
    let mut output = archive::ArchiveWriter::new(
        File::create(output_path)?,
        &sender_key.enc_sk.unwrap().to_vec(),
        &receiver_key.enc_pk.to_vec(),
        compression_level.unwrap_or(3),
    )?;
    for input_path in input_paths {
        let input_path = std::fs::canonicalize(input_path)?;
        for path in utils::generate_tree(&input_path)? {
            let object_path = get_path_components(
                path.strip_prefix(&input_path.parent().unwrap())
                    .map_err(|err| Error::new(err.to_string().as_str()))?,
            )
            .ok_or_else(|| "Error converting object path")?;
            println!(
                "Packing {} as {}",
                path.to_str().unwrap(),
                object_path.join("/")
            );
            output.write_object(path, &object_path)?;
        }
    }
    output.end()?;
    Ok(())
}

fn decrypt_file(
    input_path: &str,
    output_path: &str,
    sender: Option<&str>,
    receiver: Option<&str>,
) -> Result<(), Error> {
    let receiver_key = read_key(receiver, KeyType::FullKey)?;
    let sender_key = read_key(sender, KeyType::PublicKey)?;
    let mut input = archive::ArchiveReader::new(
        File::open(input_path)?,
        &sender_key.enc_pk.to_vec(),
        &receiver_key.enc_sk.unwrap().to_vec(),
    )?;
    let output_path = Path::new(output_path).to_path_buf();
    loop {
        let mut reader = match input.read_object()? {
            Some(reader) => reader,
            None => break,
        };
        let mut path = output_path.clone();
        reader
            .object_info
            .path
            .iter()
            .for_each(|part| path.push(part));
        if reader.object_info.object_type == ObjectType::Directory {
            fs::create_dir_all(&path)?;
            println!("Creating directory: {}", path.to_str().unwrap());
            continue;
        }
        let mut output_file = utils::HashingWriter::new(File::create(&path)?);
        std::io::copy(&mut reader, &mut output_file)?;
        if to_hex(output_file.get_hash()) != reader.object_epilogue.as_ref().unwrap().hash {
            return Err(Error::new("File hash mismatch"));
        }
        reader.object_info.epilogue = reader.object_epilogue.clone();
        println!(
            "Creating file: {}, hash={}",
            path.to_str().unwrap(),
            reader.object_epilogue.as_ref().unwrap().hash
        );
        output_file.into_inner().sync_all()?;
    }
    Ok(())
}

fn sign_file(input_path: &str, output_path: &str, signer: Option<&str>) -> Result<(), Error> {
    let key = read_key(signer, KeyType::FullKey)?;
    let mut hasher = hashing::Hasher::new();
    let mut reader = BufReader::new(File::open(input_path)?);
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let count = reader.read(buf.as_mut_slice())?;
        if count == 0 {
            break;
        }
        hasher.update(&buf[0..count]);
    }
    let hash = hasher.finalize();
    let signature = signing::sign(hash.as_slice(), &key.sig_sk.unwrap().to_vec())?;
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&signature)?;
    Ok(())
}

fn verify_signature(
    input_path: &str,
    signature_path: &str,
    signer: Option<&str>,
) -> Result<(), Error> {
    let key = read_key(signer, KeyType::PublicKey)?;
    let mut hasher = hashing::Hasher::new();
    let mut reader: Box<dyn BufRead> = match input_path {
        "-" => Box::new(BufReader::new(std::io::stdin())),
        _ => Box::new(BufReader::new(
            File::open(input_path).map_err(|err| wrap_error!("Error opening input file", err))?,
        )),
    };
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let count = reader.read(buf.as_mut_slice())?;
        if count == 0 {
            break;
        }
        hasher.update(&buf[0..count]);
    }
    let file_hash = hasher.finalize();
    let mut signature: Vec<u8> = Vec::new();
    File::open(signature_path)?.read_to_end(&mut signature)?;
    let sig_hash = signing::open(&signature, &key.sig_pk.to_vec())?;
    if file_hash != sig_hash {
        return Err("Failed to verify signature".into());
    }
    println!("Signature is valid");
    Ok(())
}

fn test_file(input_path: &str, sender: Option<&str>, receiver: Option<&str>) -> Result<(), Error> {
    let receiver_key = read_key(receiver, KeyType::FullKey)?;
    let sender_key = read_key(sender, KeyType::PublicKey)?;
    let mut input = ArchiveReader::new(
        File::open(input_path)?,
        sender_key.enc_pk.as_ref(),
        receiver_key.enc_sk.unwrap().as_ref(),
    )?;
    loop {
        let mut reader = match input.read_object()? {
            Some(reader) => reader,
            None => break,
        };
        println!("Name: {}", reader.object_info.name);
        println!("Path: {}", reader.object_info.path.join("/"));
        if reader.object_info.object_type == ObjectType::Directory {
            continue;
        }
        let mut writer = utils::HashingWriter::new(EmptyWriter {});
        io::copy(&mut reader, &mut writer)?;
        let hash1 = reader.object_epilogue.as_ref().unwrap().hash.clone();
        let hash2 = encoding::to_hex(&writer.get_hash());
        println!("Provided hash:   {}", hash1);
        println!("Calculated hash: {}", hash2);
        println!("Size: {}", reader.object_epilogue.as_ref().unwrap().size);
        if hash1 != hash2 {
            panic!("Hash mismatch");
        }
    }
    Ok(())
}

fn main() {
    let arg_vec: Vec<String> = env::args().collect();
    let args = parsing::parse_args(&arg_vec.as_slice()[1..]).unwrap();
    sodium::init().unwrap();
    println!("{:?}", args);
    let op = args.subcommand;
    let mut result: Result<(), Error> = Err(Error::new("Invalid operation"));
    if op == "encrypt" {
        let compression_level = args
            .flags
            .get("comp")
            .unwrap_or(&"6".to_string())
            .parse()
            .unwrap();
        result = encrypt_file(
            &args.positionals,
            args.flags.get("output").map(|s| s.as_str()).unwrap(),
            args.flags.get("key").map(|s| s.as_str()),
            args.flags.get("to").map(|s| s.as_str()),
            Some(compression_level),
        );
    } else if op == "decrypt" {
        result = decrypt_file(
            args.positionals[0].as_str(),
            args.flags.get("output").map(|s| s.as_str()).unwrap(),
            args.flags.get("from").map(|s| s.as_str()),
            args.flags.get("key").map(|s| s.as_str()),
        );
    } else if op == "genkey" {
        let keypair_name = args.positionals.get(0).map(|r| r.as_str());
        result = generate_key(keypair_name);
    } else if op == "pubkey" {
        let keypair_name = args.positionals.get(0).map(|r| r.as_str());
        let keypair = read_key(keypair_name, KeyType::FullKey).unwrap();
        println!("{}", to_string_pretty(&keypair.export_public()).unwrap());
        result = Ok(());
    } else if op == "sign" {
        result = sign_file(
            &args.positionals.get(0).unwrap(),
            args.flags.get("output").map(|s| s.as_str()).unwrap(),
            args.flags.get("key").map(|s| s.as_str()),
        );
    } else if op == "verify" {
        result = verify_signature(
            &args.positionals.get(0).unwrap(),
            args.flags.get("sig").map(|s| s.as_str()).unwrap(),
            args.flags.get("from").map(|s| s.as_str()),
        );
    } else if op == "test" {
        result = test_file(
            &args.positionals.get(0).unwrap(),
            args.flags.get("from").map(|s| s.as_str()),
            args.flags.get("to").map(|s| s.as_str()),
        );
    }
    if let Err(err) = result {
        println!("Error: {}", err);
        std::process::exit(1);
    }
}

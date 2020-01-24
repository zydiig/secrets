use std::env;
use std::fs::File;
use std::io::prelude::*;

extern crate byteorder;
extern crate dirs;
extern crate regex;
extern crate serde;
extern crate serde_json;

#[macro_use]
mod errors;
mod encoding;
mod keys;
mod parsing;
mod sodium;
mod streams;
use errors::Error;
use keys::{generate_key, read_key, KeyType};
use serde_json::to_string_pretty;
use sodium::{hashing, signing};
use std::io::BufReader;

const CHUNK_SIZE: usize = 32768;

fn encrypt_file(
    input_path: &str,
    output_path: &str,
    sender: Option<&str>,
    receiver: Option<&str>,
) -> errors::Result<()> {
    let sender_key = read_key(sender, KeyType::FullKey)?;
    let receiver_key = read_key(receiver, KeyType::PublicKey)?;
    let mut input_file = File::open(input_path)?;
    let mut output = streams::Stream::create(
        output_path,
        &sender_key.enc_sk.unwrap().to_vec(),
        &receiver_key.enc_pk.to_vec(),
    )?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let count = input_file.read(buf.as_mut_slice())?;
        output.write_chunk(&buf[0..count])?;
        if count == 0 {
            break;
        }
    }
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
    let mut input = streams::Stream::open(
        input_path,
        &sender_key.enc_pk.to_vec(),
        &receiver_key.enc_sk.unwrap().to_vec(),
    )?;
    let mut output_file = File::create(output_path)?;
    loop {
        let chunk = input.read_chunk()?;
        if chunk.is_empty() {
            break;
        }
        output_file.write_all(chunk.as_slice())?;
    }
    output_file.sync_all()?;
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

fn main() {
    let arg_vec: Vec<String> = env::args().collect();
    let args = parsing::parse_args(&arg_vec.as_slice()[1..]).unwrap();
    sodium::init().unwrap();
    println!("{:?}", args);
    let op = args.subcommand;
    let mut result: Result<(), Error> = Err(Error::new("Invalid operation"));
    if op == "encrypt" || op == "decrypt" {
        if op == "encrypt" {
            result = encrypt_file(
                args.positionals[0].as_str(),
                args.flags.get("output").map(|s| s.as_str()).unwrap(),
                args.flags.get("key").map(|s| s.as_str()),
                args.flags.get("to").map(|s| s.as_str()),
            );
        } else if op == "decrypt" {
            result = decrypt_file(
                args.positionals[0].as_str(),
                args.flags.get("output").map(|s| s.as_str()).unwrap(),
                args.flags.get("from").map(|s| s.as_str()),
                args.flags.get("key").map(|s| s.as_str()),
            );
        }
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
    }
    if let Err(err) = result {
        println!("Error: {}", err);
        std::process::exit(1);
    }
}

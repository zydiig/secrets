extern crate byteorder;
extern crate serde;
extern crate serde_json;
extern crate strum;
#[macro_use]
extern crate strum_macros;

use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::{env, io};

use errors::Error;

use std::path::Path;

use crate::archive::{ArchiveReader, ArchiveWriter};
use crate::sodium::to_hex;
use crate::utils::EmptyWriter;
use archive::object::ObjectType;

#[macro_use]
mod errors;
mod archive;
mod buffer;
mod parsing;
mod sodium;
mod utils;
mod zstd;

fn get_password(args: &parsing::Arguments) -> Result<String, String> {
    if args.flags.contains_key("password") && args.flags.contains_key("passfile") {
        return Err("-p/--password and -P/--passfile are in conflict".into());
    }
    if let Some(password) = args.flags.get("password") {
        Ok(password.clone())
    } else if let Some(passfile) = args.flags.get("passfile") {
        let mut password = String::new();
        File::open(passfile)
            .and_then(|ref mut file| file.read_to_string(&mut password))
            .map_err(|err| format!("Error reading from passfile: {}", err))?;
        Ok(password)
    } else {
        Err("Please specify password or passfile".into())
    }
}

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
    password: &str,
    compression_level: Option<i32>,
) -> errors::Result<()> {
    let mut output = ArchiveWriter::new(
        File::create(output_path)?,
        password,
        compression_level.unwrap_or(3),
    )?;
    for input_path in input_paths {
        let input_path = Path::new(input_path);
        for path in utils::generate_tree(&input_path, true)? {
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
            output.write_object(&path, &object_path).map_err(|err| {
                wrap_error!(
                    format!("Error opening {}", path.as_path().to_string_lossy()).as_str(),
                    err
                )
            })?;
        }
    }
    output.end()?;
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Error> {
    let mut input = archive::ArchiveReader::new(File::open(input_path)?, &password)?;
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
        if to_hex(&output_file.get_hash()) != reader.object_epilogue.as_ref().unwrap().hash {
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

fn test_file(input_path: &str, password: &str) -> Result<(), Error> {
    let mut input = ArchiveReader::new(File::open(input_path)?, &password)?;
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
        let hash2 = sodium::to_hex(&writer.get_hash());
        if hash1 != hash2 {
            panic!("Hash mismatch");
        }
        println!("Hash: {}", &hash1);
        println!("Size: {}", reader.object_epilogue.as_ref().unwrap().size);
        println!();
    }
    Ok(())
}

fn main() {
    let arg_vec: Vec<String> = env::args().collect();
    let args = parsing::parse_args(&arg_vec.as_slice()[1..]).unwrap();
    sodium::init().unwrap();
    println!("{:?}", &args);
    let op = &args.subcommand;
    let mut result: Result<(), Error> = Err(Error::new("Invalid operation"));
    if op == "encrypt" {
        let compression_level = args
            .flags
            .get("comp")
            .unwrap_or(&"3".to_string())
            .parse()
            .unwrap();
        result = encrypt_file(
            &args.positionals,
            args.flags.get("output").map(|s| s.as_str()).unwrap(),
            get_password(&args).unwrap().as_str(),
            Some(compression_level),
        );
    } else if op == "decrypt" {
        result = decrypt_file(
            args.positionals[0].as_str(),
            args.flags.get("output").map(|s| s.as_str()).unwrap(),
            get_password(&args).unwrap().as_str(),
        );
    } else if op == "test" {
        result = test_file(
            &args.positionals.get(0).unwrap(),
            get_password(&args).unwrap().as_str(),
        );
    }
    if let Err(err) = result {
        println!("Error: {}", err);
        std::process::exit(1);
    }
}

extern crate secrets;

use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::{env, io};

use std::path::Path;

use crate::archive::{ArchiveReader, ArchiveWriter, ChunkType, Manifest};
use crate::sodium::to_hex;
use crate::utils::EmptyWriter;
use archive::object::ObjectType;
use failure::{ensure, err_msg, format_err, Backtrace, Error, Fail, ResultExt};

use secrets::*;

use utils::get_password;

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
    compression_level: i32,
    volume_size: Option<u64>,
) -> Result<(), Error> {
    let mut output = ArchiveWriter::new(output_path, password, compression_level, volume_size)?;
    for input_path in input_paths {
        let input_path = Path::new(input_path);
        for path in utils::generate_tree(&input_path, true)? {
            let object_path = get_path_components(
                path.strip_prefix(&input_path.parent().unwrap())
                    .context("Error transforming path")?,
            )
            .ok_or_else(|| err_msg("Error converting object path"))?;
            println!(
                "Packing {} as {}",
                path.to_str().unwrap(),
                object_path.join("/")
            );
            output
                .write_object(&path, &object_path)
                .context("Error packing object")?;
        }
    }
    output.end()?;
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, password: &str) -> Result<(), Error> {
    let mut input = archive::ArchiveReader::new(input_path, &password)?;
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
            return Err(err_msg("File hash mismatch"));
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
    let mut input = ArchiveReader::new(input_path, &password)?;
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
        ensure!(hash1 == hash2, "Hash mismatch");
        println!("Hash: {}", &hash1);
        println!("Size: {}", reader.object_epilogue.as_ref().unwrap().size);
        println!();
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&input.manifest.unwrap())?
    );
    Ok(())
}

fn main() {
    let arg_vec: Vec<String> = env::args().collect();
    let mut parser = parsing::Parser::new();
    parser.add_argument("output", Some("o"), 1);
    parser.add_argument("comp", Some("c"), 1);
    parser.add_argument("volume", Some("v"), 1);
    parser.add_argument("passfile", Some("P"), 1);
    parser.add_argument("password", Some("p"), 1);
    let args = parser.parse_args(&arg_vec[2..]).unwrap();
    sodium::init().unwrap();
    println!("{:?}", &args);
    let op = &arg_vec[1];
    let mut result: Result<(), Error> = Err(err_msg("Invalid operation"));
    if op == "encrypt" {
        let compression_level = args
            .flags
            .get("comp")
            .map(|o| o.as_ref().unwrap().as_str())
            .or(Some("3"))
            .unwrap()
            .parse::<i32>()
            .unwrap();
        let volume_size = args
            .flags
            .get("volume")
            .map(|o| o.as_ref().unwrap())
            .map(|v| utils::parse_size(v))
            .transpose()
            .unwrap();
        println!("{:?}", volume_size);
        result = encrypt_file(
            &args.positionals,
            args.flags
                .get("output")
                .map(|s| s.as_ref().unwrap().as_str())
                .unwrap(),
            get_password(&args).unwrap().as_str(),
            compression_level,
            volume_size,
        );
    } else if op == "decrypt" {
        result = decrypt_file(
            args.positionals[0].as_str(),
            args.flags
                .get("output")
                .map(|s| s.as_ref().unwrap().as_str())
                .unwrap(),
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
        println!("{}", err.backtrace());
        std::process::exit(1);
    }
}

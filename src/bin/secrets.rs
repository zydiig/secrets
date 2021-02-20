extern crate secrets;

use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use clap::Clap;
use failure::{ensure, err_msg, Error, ResultExt};

use archive::object::ObjectType;
use secrets::*;

use crate::archive::{ArchiveReader, ArchiveWriter};
use crate::sodium::to_hex;
use crate::utils::EmptyWriter;

fn read_file_content<P: AsRef<Path>>(path: P) -> Result<String, failure::Error> {
    let mut content = String::new();
    File::open(path.as_ref())
        .and_then(|ref mut file| file.read_to_string(&mut content))
        .context("Error reading from file")?;
    Ok(content)
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

#[derive(Clap, Debug)]
#[clap(version = "0.0.1")]
struct Opts {
    #[clap(short = 'P', long = "passfile", global = true)]
    password_file: Option<PathBuf>,
    #[clap(short = 'p', long = "password", global = true)]
    password: Option<String>,
    #[clap(subcommand)]
    subcommand: Subcommands,
}

#[derive(Clap, Debug)]
enum Subcommands {
    #[clap()]
    Encrypt {
        #[clap(short = 'o', long = "output")]
        output: String,
        #[clap(short = 'c', long = "comp", default_value = "3")]
        compression_level: i32,
        #[clap(short = 'v', long = "volume", parse(try_from_str = utils::parse_size))]
        volume_size: Option<u64>,
        #[clap(required = true)]
        input: Vec<String>,
    },
    Decrypt {
        #[clap(short = 'o', long = "output")]
        output: Option<String>,
        #[clap(required = true)]
        input: String,
    },
    Test {
        #[clap(required = true)]
        input: String,
    },
}

fn main() {
    let opts: Opts = Opts::parse();
    println!("{:?}", opts);
    sodium::init().unwrap();
    let password = match opts.password {
        Some(password) => password,
        None => read_file_content(opts.password_file.unwrap())
            .unwrap()
            .trim()
            .to_owned(),
    };
    let result: Result<(), Error> = match opts.subcommand {
        Subcommands::Encrypt {
            compression_level,
            volume_size,
            output,
            input,
        } => encrypt_file(
            &input,
            &output,
            &password,
            Some(compression_level),
            volume_size,
        ),
        Subcommands::Decrypt { output, input } => {
            decrypt_file(&input, &output.unwrap_or(".".to_owned()), &password)
        }
        Subcommands::Test { input } => test_file(&input, &password),
    };
    if let Err(err) = result {
        println!("Error: {}", err);
        println!("{}", err.backtrace());
        std::process::exit(1);
    }
}

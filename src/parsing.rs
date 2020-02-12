use failure::{err_msg, Error};
use serde::private::ser::constrain;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Arguments {
    pub flags: HashMap<String, Option<String>>,
    pub positionals: Vec<String>,
}

pub struct Parser {
    pub short_flags: HashMap<String, String>,
    pub long_flags: HashMap<String, u32>,
}

impl Parser {
    pub fn new() -> Self {
        Self {
            short_flags: HashMap::new(),
            long_flags: HashMap::new(),
        }
    }

    pub fn add_argument(&mut self, long_form: &str, short_form: Option<&str>, count: u32) {
        if long_form.is_empty() {
            panic!("Long form needed");
        }
        if let Some(short_form) = short_form {
            if short_form.is_empty() {
                panic!("Invalid short form");
            }
            self.short_flags.insert(short_form.into(), long_form.into());
        }
        self.long_flags.insert(long_form.into(), count);
    }

    pub fn parse_args(&self, args: &[String]) -> Result<Arguments, Error> {
        let mut flags: HashMap<String, Option<String>> = HashMap::new();
        let mut index = 0usize;
        let mut positionals: Vec<String> = Vec::new();
        while index < args.len() {
            let arg = &args[index];
            let mut flag_name = None;
            if !arg.starts_with("--") && arg.starts_with("-") {
                flag_name = Some(
                    self.short_flags
                        .get(&arg[1..])
                        .ok_or_else(|| err_msg("Invalid short flag"))?
                        .to_string(),
                );
            } else if arg.starts_with("--") {
                flag_name = Some(arg[2..].to_string());
            }
            if let Some(flag_name) = flag_name {
                let count = *self
                    .long_flags
                    .get(&flag_name)
                    .ok_or_else(|| err_msg("Invalid long flag"))?;
                if count > 0 {
                    flags.insert(
                        flag_name.clone(),
                        Some(
                            args.get(index + 1)
                                .ok_or_else(|| err_msg("No value provided for flag"))?
                                .clone(),
                        ),
                    );
                    index += 2;
                } else {
                    flags.insert(flag_name.clone(), None);
                    index += 1;
                }
            } else {
                positionals.push(arg.clone());
                index += 1;
            }
        }
        Ok(Arguments { flags, positionals })
    }
}

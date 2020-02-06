use std::collections::HashMap;

#[derive(Debug)]
pub struct Arguments {
    pub subcommand: String,
    pub flags: HashMap<String, String>,
    pub positionals: Vec<String>,
}

pub fn parse_args(args: &[String]) -> Result<Arguments, String> {
    let subcommand = args[0].clone();
    let mut flags: HashMap<String, String> = HashMap::new();
    let mut index = 1usize;
    let mut positionals: Vec<String> = Vec::new();
    let flag_defs = vec![
        ("o", "output"),
        ("c", "comp"),
        ("p", "password"),
        ("P", "passfile"),
    ];
    while index < args.len() {
        let arg = &args[index];
        let mut skip = false;
        for (short_def, long_def) in flag_defs.iter() {
            if (!short_def.is_empty() && format!("-{}", short_def) == arg.as_str())
                || format!("--{}", long_def) == arg.as_str()
            {
                flags.insert(
                    String::from(*long_def),
                    args.get(index + 1)
                        .ok_or_else(|| format!("No argument provided for option {}", long_def))?
                        .clone(),
                );
                index += 2;
                skip = true;
                break;
            }
        }
        if skip {
            continue;
        }
        positionals.push(args[index].to_string());
        index += 1;
    }
    Ok(Arguments {
        subcommand,
        flags,
        positionals,
    })
}

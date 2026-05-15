// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// parses command-line arguments into a structured config

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum Subsystem {
    Console,
    Windows,
}

impl Subsystem {
    // converts string to subsystem variant
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "console" => Ok(Subsystem::Console),
            "windows" => Ok(Subsystem::Windows),
            other => Err(format!("unknown subsystem: '{}', expected 'console' or 'windows'", other)),
        }
    }

    // returns numeric value written into PE optional header
    pub fn value(&self) -> u16 {
        match self {
            Subsystem::Console => 3,
            Subsystem::Windows => 2,
        }
    }
}

#[derive(Debug)]
pub struct Config {
    pub inputs: Vec<PathBuf>,
    pub output: PathBuf,
    pub subsystem: Subsystem,
    pub entry: String,
    pub libs: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            inputs: Vec::new(),
            output: PathBuf::from("out.exe"),
            subsystem: Subsystem::Console,
            entry: String::from("main"),
            libs: Vec::new(),
        }
    }
}

// parses raw argv slice into Config or returns an error string
pub fn parse(args: &[String]) -> Result<Config, String> {
    if args.is_empty() {
        return Err(usage());
    }

    let mut cfg = Config::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-o" => {
                i += 1;
                let val = next_value(&args, i, "-o")?;
                cfg.output = PathBuf::from(val);
            }
            "--subsystem" => {
                i += 1;
                let val = next_value(&args, i, "--subsystem")?;
                cfg.subsystem = Subsystem::from_str(val)?;
            }
            "--entry" => {
                i += 1;
                let val = next_value(&args, i, "--entry")?;
                cfg.entry = val.to_string();
            }
            "--lib" => {
                i += 1;
                let val = next_value(&args, i, "--lib")?;
                cfg.libs.push(PathBuf::from(val));
            }
            "-h" | "--help" => {
                return Err(usage());
            }
            "-v" | "--version" => {
                return Err(format!("wlnk {}", env!("CARGO_PKG_VERSION")));
            }
            arg if arg.starts_with('-') => {
                return Err(format!("unknown flag: '{}'", arg));
            }
            // positional argument treated as input file
            arg => {
                cfg.inputs.push(PathBuf::from(arg));
            }
        }
        i += 1;
    }

    validate(cfg)
}

fn next_value<'a>(args: &'a [String], i: usize, flag: &str) -> Result<&'a str, String> {
    args.get(i)
        .map(|s| s.as_str())
        .ok_or_else(|| format!("flag '{}' requires a value", flag))
}

fn validate(cfg: Config) -> Result<Config, String> {
    if cfg.inputs.is_empty() {
        return Err("no input files provided".to_string());
    }
    Ok(cfg)
}

pub fn usage() -> String {
    r#"wlnk - lightweight PE (x64) linker

usage:
    wlnk <input.obj> [input2.obj ...] -o <output.exe> [flags]

flags:
    -o <path>             output file (default: out.exe)
    --subsystem <name>    console | windows (default: console)
    --entry <symbol>      entry point symbol (default: main)
    --lib <path>          path to .lib directory (repeatable)
    -h, --help            show this help
    -v, --version         show version"#
        .to_string()
}

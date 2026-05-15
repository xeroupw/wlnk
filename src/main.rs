// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// wlnk - lightweight PE (x64) linker entry point

mod cli;
mod coff;
mod error;
mod linker;
mod pe;
mod reloc;
mod symtab;

use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let cfg = match cli::parse(&args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("{}", msg);
            process::exit(1);
        }
    };

    if let Err(e) = linker::run(&cfg) {
        eprintln!("wlnk: error: {}", e);
        process::exit(1);
    }
}

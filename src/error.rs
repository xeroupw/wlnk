// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// unified error type for the linker

use std::fmt;

#[derive(Debug)]
#[allow(dead_code)]
pub enum LinkError {
    Cli(String),
    Io(std::io::Error),
    Coff(String),
    Reloc(String),
    Pe(String),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::Cli(msg) => write!(f, "cli error: {}", msg),
            LinkError::Io(e) => write!(f, "io error: {}", e),
            LinkError::Coff(msg) => write!(f, "coff error: {}", msg),
            LinkError::Reloc(msg) => write!(f, "relocation error: {}", msg),
            LinkError::Pe(msg) => write!(f, "pe error: {}", msg),
        }
    }
}

impl From<std::io::Error> for LinkError {
    fn from(e: std::io::Error) -> Self {
        LinkError::Io(e)
    }
}

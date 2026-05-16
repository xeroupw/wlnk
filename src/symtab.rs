// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// builds a global symbol table from all input COFF objects
// resolves symbol references and detects duplicates / undefined symbols

use std::collections::HashMap;
use crate::error::LinkError;

#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    // index of the object file this symbol comes from
    pub obj_index: usize,
    // index within that object's section list
    pub section_index: usize,
    // byte offset within the section
    pub offset: u32,
    // true if the symbol is exported (external storage class)
    pub is_external: bool,
}

#[derive(Debug)]
pub struct SymbolTable {
    pub map: HashMap<String, ResolvedSymbol>,
    // undefined externals collected during resolution
    pub undefined: Vec<String>,
}

impl SymbolTable {
    pub fn new() -> Self {
        SymbolTable {
            map: HashMap::new(),
            undefined: Vec::new(),
        }
    }

    // ingests symbols from one parsed COFF object
    pub fn ingest(&mut self, obj_index: usize, symbols: &[crate::coff::Symbol]) -> Result<(), LinkError> {
        for sym in symbols {
            if !sym.is_external() {
                continue;
            }

            if !sym.is_defined() {
                // record as potentially undefined; resolved later when all objects are ingested
                continue;
            }

            let section_index = (sym.section_number - 1) as usize;

            let resolved = ResolvedSymbol {
                obj_index,
                section_index,
                offset: sym.value,
                is_external: true,
            };

            if self.map.contains_key(&sym.name) {
                return Err(LinkError::Coff(format!(
                    "duplicate symbol: '{}'", sym.name
                )));
            }

            self.map.insert(sym.name.clone(), resolved);
        }

        Ok(())
    }

    // checks for unresolved external symbols after all objects are ingested
    pub fn collect_undefined(&mut self, symbols: &[crate::coff::Symbol]) {
        for sym in symbols {
            if sym.is_external() && !sym.is_defined() && !self.map.contains_key(&sym.name) {
                if !self.undefined.contains(&sym.name) {
                    self.undefined.push(sym.name.clone());
                }
            }
        }
    }

    // verifies entry point symbol exists
    pub fn check_entry(&self, entry: &str) -> Result<(), LinkError> {
        if !self.map.contains_key(entry) {
            Err(LinkError::Coff(format!(
                "entry point symbol '{}' not found", entry
            )))
        } else {
            Ok(())
        }
    }

    // reports all undefined symbols as one error
    #[allow(dead_code)]
    pub fn report_undefined(&self) -> Result<(), LinkError> {
        if self.undefined.is_empty() {
            return Ok(());
        }
        let list = self.undefined.join(", ");
        Err(LinkError::Coff(format!("undefined symbols: {}", list)))
    }
}

// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// builds the PE import table (.idata section) from .lib files
// ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use crate::error::LinkError;

// one imported symbol from a DLL
#[derive(Debug, Clone)]
pub struct ImportSymbol {
    pub name: String,
    // hint is the ordinal hint from the .lib — 0 if unknown
    pub hint: u16,
}

// all symbols imported from one DLL
#[derive(Debug, Clone)]
pub struct ImportDll {
    pub dll_name: String,
    pub symbols: Vec<ImportSymbol>,
}

// fully built .idata blob with VA fixup info
pub struct ImportTable {
    // raw bytes of the complete .idata section
    pub data: Vec<u8>,
    // maps symbol name -> RVA of its IAT slot (8-byte entry, holds address at runtime)
    pub iat_rvas: HashMap<String, u32>,
    // RVA of the import directory table (IMAGE_IMPORT_DESCRIPTOR array)
    pub directory_rva: u32,
}

// searches lib directories for .lib files and parses imported symbols
// only reads COFF import library short records (second linker member / per-symbol entries)
pub fn collect_imports(
    lib_dirs: &[PathBuf],
    referenced: &[String],
) -> Result<Vec<ImportDll>, LinkError> {
    let mut by_dll: HashMap<String, ImportDll> = HashMap::new();

    for dir in lib_dirs {
        if !dir.exists() {
            continue;
        }
        let entries = fs::read_dir(dir).map_err(|e| LinkError::Io(e))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("lib") {
                continue;
            }
            let data = match fs::read(&path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            parse_lib(&data, referenced, &mut by_dll)?;
        }
    }

    Ok(by_dll.into_values().collect())
}

// parses an AR-format .lib archive and extracts import short records
fn parse_lib(
    data: &[u8],
    referenced: &[String],
    by_dll: &mut HashMap<String, ImportDll>,
) -> Result<(), LinkError> {
    // AR magic: "!<arch>\n"
    if data.len() < 8 || &data[..8] != b"!<arch>\n" {
        return Ok(());
    }

    let mut pos = 8usize;

    while pos + 60 <= data.len() {
        // AR member header is 60 bytes
        let _name_bytes = &data[pos..pos+16];
        let size_bytes = &data[pos+48..pos+58];

        let size_str = std::str::from_utf8(size_bytes)
            .unwrap_or("0")
            .trim();
        let member_size: usize = size_str.parse().unwrap_or(0);

        pos += 60;
        let member_data = data.get(pos..pos+member_size).unwrap_or(&[]);

        // import short record: machine(2) + sig1(2)=0 + sig2(2)=0xFFFF
        // actual layout: sig1=0x0000, sig2=0xFFFF, version, machine, time, size, hint, type/nametype
        if member_size >= 20 {
            let sig1 = u16::from_le_bytes([member_data[0], member_data[1]]);
            let sig2 = u16::from_le_bytes([member_data[2], member_data[3]]);

            if sig1 == 0x0000 && sig2 == 0xFFFF {
                // this is an import short record
                let hint = u16::from_le_bytes([member_data[12], member_data[13]]);
                // strings follow: symbol_name\0 dll_name\0
                let strings_start = 20;
                if let Some(sym_end) = member_data[strings_start..].iter().position(|&b| b == 0) {
                    let sym_name = String::from_utf8_lossy(
                        &member_data[strings_start..strings_start+sym_end]
                    ).into_owned();

                    let dll_start = strings_start + sym_end + 1;
                    if let Some(dll_end) = member_data[dll_start..].iter().position(|&b| b == 0) {
                        let dll_name = String::from_utf8_lossy(
                            &member_data[dll_start..dll_start+dll_end]
                        ).into_owned().to_lowercase();

                        if referenced.contains(&sym_name) {
                            let entry = by_dll.entry(dll_name.clone()).or_insert_with(|| ImportDll {
                                dll_name: dll_name.clone(),
                                symbols: Vec::new(),
                            });
                            if !entry.symbols.iter().any(|s| s.name == sym_name) {
                                entry.symbols.push(ImportSymbol { name: sym_name, hint });
                            }
                        }
                    }
                }
            }
        }

        // advance, keeping AR 2-byte alignment
        pos += member_size;
        if pos % 2 != 0 {
            pos += 1;
        }
    }

    Ok(())
}

// builds the raw .idata section bytes and returns import table metadata
// layout per DLL:
//   IMAGE_IMPORT_DESCRIPTOR (20 bytes each) + null terminator
//   import lookup table (ILT): array of 8-byte entries per symbol + null
//   import address table (IAT): same layout as ILT, patched by loader at runtime
//   hint/name table: u16 hint + name + null byte (word-aligned)
//   DLL name strings
pub fn build(dlls: &[ImportDll], section_rva: u32) -> Result<ImportTable, LinkError> {
    if dlls.is_empty() {
        return Ok(ImportTable {
            data: Vec::new(),
            iat_rvas: HashMap::new(),
            directory_rva: 0,
        });
    }

    let num_dlls = dlls.len();

    // pass 1: compute sizes and offsets
    // IMAGE_IMPORT_DESCRIPTOR array: (num_dlls + 1) * 20 bytes
    let dir_size = (num_dlls + 1) * 20;

    // per-dll ILT and IAT each hold (num_symbols + 1) * 8 bytes
    let mut ilt_offsets: Vec<usize> = Vec::new();
    let mut iat_offsets: Vec<usize> = Vec::new();
    let mut hint_offsets: Vec<Vec<usize>> = Vec::new();
    let mut dll_name_offsets: Vec<usize> = Vec::new();

    let mut cur = dir_size;

    // ILT block
    for dll in dlls {
        ilt_offsets.push(cur);
        cur += (dll.symbols.len() + 1) * 8;
    }

    // IAT block (same size as ILT)
    for dll in dlls {
        iat_offsets.push(cur);
        cur += (dll.symbols.len() + 1) * 8;
    }

    // hint/name table
    for dll in dlls {
        let mut sym_offsets = Vec::new();
        for sym in &dll.symbols {
            sym_offsets.push(cur);
            cur += 2 + sym.name.len() + 1;
            if cur % 2 != 0 { cur += 1; }
        }
        hint_offsets.push(sym_offsets);
    }

    // DLL name strings
    for dll in dlls {
        dll_name_offsets.push(cur);
        cur += dll.dll_name.len() + 1;
        if cur % 2 != 0 { cur += 1; }
    }

    let total = cur;
    let mut data = vec![0u8; total];
    let mut iat_rvas: HashMap<String, u32> = HashMap::new();

    // pass 2: write IMAGE_IMPORT_DESCRIPTORs
    for i in 0..dlls.len() {
        let desc_off = i * 20;
        let ilt_rva = section_rva + ilt_offsets[i] as u32;
        let iat_rva = section_rva + iat_offsets[i] as u32;
        let name_rva = section_rva + dll_name_offsets[i] as u32;

        write_u32(&mut data, desc_off, ilt_rva);
        write_u32(&mut data, desc_off + 4, 0); // timestamp (filled by loader)
        write_u32(&mut data, desc_off + 8, 0); // forwarder chain
        write_u32(&mut data, desc_off + 12, name_rva);
        write_u32(&mut data, desc_off + 16, iat_rva);
        // null terminator descriptor is already zeroed
    }

    // write ILT, IAT, hint/name table
    for (i, dll) in dlls.iter().enumerate() {
        for (j, sym) in dll.symbols.iter().enumerate() {
            let hint_rva = section_rva + hint_offsets[i][j] as u32;
            // high bit clear = import by name (bit 63 set = by ordinal)
            let entry_val: u64 = hint_rva as u64;

            let ilt_entry_off = ilt_offsets[i] + j * 8;
            write_u64(&mut data, ilt_entry_off, entry_val);

            let iat_entry_off = iat_offsets[i] + j * 8;
            write_u64(&mut data, iat_entry_off, entry_val);

            // record RVA of IAT slot for relocation patching
            iat_rvas.insert(sym.name.clone(), section_rva + iat_entry_off as u32);

            // write hint/name entry
            let hn_off = hint_offsets[i][j];
            write_u16_at(&mut data, hn_off, sym.hint);
            let name_bytes = sym.name.as_bytes();
            data[hn_off+2..hn_off+2+name_bytes.len()].copy_from_slice(name_bytes);
            // null terminator already zero
        }
        // null terminator entries for ILT and IAT are already zeroed

        // write DLL name
        let dn_off = dll_name_offsets[i];
        let dll_bytes = dll.dll_name.as_bytes();
        data[dn_off..dn_off+dll_bytes.len()].copy_from_slice(dll_bytes);
    }

    Ok(ImportTable {
        data,
        iat_rvas,
        directory_rva: section_rva,
    })
}

fn write_u32(data: &mut Vec<u8>, off: usize, val: u32) {
    data[off..off+4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(data: &mut Vec<u8>, off: usize, val: u64) {
    data[off..off+8].copy_from_slice(&val.to_le_bytes());
}

fn write_u16_at(data: &mut Vec<u8>, off: usize, val: u16) {
    data[off..off+2].copy_from_slice(&val.to_le_bytes());
}

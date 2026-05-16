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
    // undecorated name as it appears in the DLL export table (e.g. "WriteFile")
    pub export_name: String,
    // name used in object files to reference via IAT pointer (e.g. "__imp_WriteFile")
    pub imp_name: String,
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
    pub data: Vec<u8>,
    // maps imp_name -> RVA of its IAT slot
    pub iat_rvas: HashMap<String, u32>,
    pub directory_rva: u32,
}

// searches lib directories for .lib files and collects imports for referenced symbols
// referenced contains raw symbol names as seen in COFF undefined externals,
// which may be "__imp_WriteFile" style (indirect) or "WriteFile" style (direct)
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

// parses an AR-format .lib archive and extracts COFF import short records
fn parse_lib(
    data: &[u8],
    referenced: &[String],
    by_dll: &mut HashMap<String, ImportDll>,
) -> Result<(), LinkError> {
    if data.len() < 8 || &data[..8] != b"!<arch>\n" {
        return Ok(());
    }

    let mut pos = 8usize;

    while pos + 60 <= data.len() {
        let size_bytes = &data[pos+48..pos+58];
        let member_size: usize = std::str::from_utf8(size_bytes)
            .unwrap_or("0")
            .trim()
            .parse()
            .unwrap_or(0);

        pos += 60;
        let member_data = match data.get(pos..pos+member_size) {
            Some(d) => d,
            None => break,
        };

        // COFF import short record signature: sig1=0x0000, sig2=0xFFFF
        // layout: sig1(2) sig2(2) version(2) machine(2) timeDateStamp(4)
        //         sizeOfData(4) ordinalOrHint(2) type:nameType(2)
        //         symbol_name\0 dll_name\0
        if member_size >= 20 {
            let sig1 = u16::from_le_bytes([member_data[0], member_data[1]]);
            let sig2 = u16::from_le_bytes([member_data[2], member_data[3]]);

            if sig1 == 0x0000 && sig2 == 0xFFFF {
                let hint = u16::from_le_bytes([member_data[12], member_data[13]]);
                let name_type = (member_data[15] >> 2) & 0x7;

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

                        // derive both the export name and the __imp_ variant
                        // name_type 0 = no prefix, 1 = no underscore, 2 = undecorate
                        let export_name = undecorate(&sym_name, name_type);
                        let imp_name = format!("__imp_{}", export_name);

                        // match if any referenced symbol names this import
                        // either as direct call (export_name) or indirect (__imp_ pointer)
                        let is_referenced = referenced.iter().any(|r| {
                            r == &sym_name || r == &export_name || r == &imp_name
                        });

                        if is_referenced {
                            let entry = by_dll.entry(dll_name.clone()).or_insert_with(|| ImportDll {
                                dll_name: dll_name.clone(),
                                symbols: Vec::new(),
                            });
                            if !entry.symbols.iter().any(|s| s.export_name == export_name) {
                                entry.symbols.push(ImportSymbol {
                                    export_name,
                                    imp_name,
                                    hint,
                                });
                            }
                        }
                    }
                }
            }
        }

        pos += member_size;
        if pos % 2 != 0 {
            pos += 1;
        }
    }

    Ok(())
}

// strips common MSVC decoration from symbol name to get the export name
// name_type from the import short record controls which stripping applies
fn undecorate(name: &str, name_type: u8) -> String {
    match name_type {
        // IMPORT_NAME_UNDECORATE: strip leading '?' or '_', strip trailing '@...'
        2 => {
            let s = name.trim_start_matches('_').trim_start_matches('?');
            if let Some(at) = s.find('@') {
                s[..at].to_string()
            } else {
                s.to_string()
            }
        }
        // IMPORT_NAME_NO_PREFIX: strip leading '_' or '@' or '?'
        1 => name.trim_start_matches(|c| c == '_' || c == '@' || c == '?').to_string(),
        // IMPORT_NAME: use as-is (already the export name)
        _ => name.to_string(),
    }
}

// builds the raw .idata section and returns metadata for relocation patching
// layout:
//   IMAGE_IMPORT_DESCRIPTOR array — (num_dlls + 1) * 20 bytes, null-terminated
//   ILT per DLL — (num_symbols + 1) * 8 bytes, null-terminated
//   IAT per DLL — same layout as ILT, patched by loader at runtime
//   hint/name entries — u16 hint + ASCII name + null + optional pad byte
//   DLL name strings — ASCII + null + optional pad byte
pub fn build(dlls: &[ImportDll], section_rva: u32) -> Result<ImportTable, LinkError> {
    if dlls.is_empty() {
        return Ok(ImportTable {
            data: Vec::new(),
            iat_rvas: HashMap::new(),
            directory_rva: 0,
        });
    }

    let num_dlls = dlls.len();
    let dir_size = (num_dlls + 1) * 20;

    let mut ilt_offsets: Vec<usize> = Vec::new();
    let mut iat_offsets: Vec<usize> = Vec::new();
    let mut hint_offsets: Vec<Vec<usize>> = Vec::new();
    let mut dll_name_offsets: Vec<usize> = Vec::new();

    let mut cur = dir_size;

    for dll in dlls {
        ilt_offsets.push(cur);
        cur += (dll.symbols.len() + 1) * 8;
    }

    for dll in dlls {
        iat_offsets.push(cur);
        cur += (dll.symbols.len() + 1) * 8;
    }

    for dll in dlls {
        let mut sym_offsets = Vec::new();
        for sym in &dll.symbols {
            sym_offsets.push(cur);
            cur += 2 + sym.export_name.len() + 1;
            if cur % 2 != 0 { cur += 1; }
        }
        hint_offsets.push(sym_offsets);
    }

    for dll in dlls {
        dll_name_offsets.push(cur);
        cur += dll.dll_name.len() + 1;
        if cur % 2 != 0 { cur += 1; }
    }

    let mut data = vec![0u8; cur];
    let mut iat_rvas: HashMap<String, u32> = HashMap::new();

    // write IMAGE_IMPORT_DESCRIPTORs
    for i in 0..num_dlls {
        let off = i * 20;
        write_u32(&mut data, off, section_rva + ilt_offsets[i] as u32);
        write_u32(&mut data, off + 4, 0);
        write_u32(&mut data, off + 8, 0);
        write_u32(&mut data, off + 12, section_rva + dll_name_offsets[i] as u32);
        write_u32(&mut data, off + 16, section_rva + iat_offsets[i] as u32);
    }
    // null terminator descriptor is already zeroed

    // write ILT, IAT, hint/name entries
    for (i, dll) in dlls.iter().enumerate() {
        for (j, sym) in dll.symbols.iter().enumerate() {
            let hint_rva = section_rva + hint_offsets[i][j] as u32;
            // bit 63 clear = import by name
            let entry_val: u64 = hint_rva as u64;

            write_u64(&mut data, ilt_offsets[i] + j * 8, entry_val);
            write_u64(&mut data, iat_offsets[i] + j * 8, entry_val);

            // record both the imp_name and export_name -> IAT slot RVA
            let iat_slot_rva = section_rva + iat_offsets[i] as u32 + j as u32 * 8;
            iat_rvas.insert(sym.imp_name.clone(), iat_slot_rva);
            iat_rvas.insert(sym.export_name.clone(), iat_slot_rva);

            // hint/name entry
            let hn = hint_offsets[i][j];
            write_u16_at(&mut data, hn, sym.hint);
            let nb = sym.export_name.as_bytes();
            data[hn+2..hn+2+nb.len()].copy_from_slice(nb);
        }

        // DLL name string
        let dn = dll_name_offsets[i];
        let db = dll.dll_name.as_bytes();
        data[dn..dn+db.len()].copy_from_slice(db);
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

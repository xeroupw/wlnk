// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// orchestrates the full link pipeline:
// load .obj files -> merge sections -> build symbol table -> apply relocations -> emit PE
// ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

use std::collections::HashMap;
use std::fs;

use crate::cli::Config;
use crate::coff;
use crate::error::LinkError;
use crate::idata;
use crate::pe::{
    OutputSection, PeBuilder, IMAGE_BASE, SECTION_ALIGN,
    align_up, section_characteristics_for,
};
use crate::reloc::{self, RelocationContext};
use crate::symtab::SymbolTable;

// section data merged from all input objects
struct MergedSection {
    name: String,
    characteristics: u32,
    data: Vec<u8>,
    // maps (obj_index, section_index) -> byte offset within merged data
    offsets: HashMap<(usize, usize), u32>,
}

impl MergedSection {
    fn new(name: String, characteristics: u32) -> Self {
        MergedSection {
            name,
            characteristics,
            data: Vec::new(),
            offsets: HashMap::new(),
        }
    }

    fn append(&mut self, obj_index: usize, sec_index: usize, data: &[u8]) -> u32 {
        let offset = self.data.len() as u32;
        self.offsets.insert((obj_index, sec_index), offset);
        self.data.extend_from_slice(data);
        let pad = align_up(self.data.len() as u32, 16) as usize - self.data.len();
        self.data.extend(std::iter::repeat(0).take(pad));
        offset
    }
}

pub fn run(cfg: &Config) -> Result<(), LinkError> {
    // 1. load and parse all input .obj files
    let mut objects: Vec<coff::CoffObject> = Vec::new();
    for path in &cfg.inputs {
        let raw = fs::read(path).map_err(|e| {
            LinkError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot read '{}': {}", path.display(), e),
            ))
        })?;
        let obj = coff::parse(&raw)?;
        objects.push(obj);
    }

    // 2. build global symbol table
    let mut symtab = SymbolTable::new();
    for (idx, obj) in objects.iter().enumerate() {
        symtab.ingest(idx, &obj.symbols)?;
    }
    for obj in &objects {
        symtab.collect_undefined(&obj.symbols);
    }

    // 3. collect undefined externals — these are candidates for DLL imports
    let undefined: Vec<String> = symtab.undefined.clone();

    // 4. resolve imports from .lib directories
    let import_dlls = if !cfg.libs.is_empty() && !undefined.is_empty() {
        idata::collect_imports(&cfg.libs, &undefined)?
    } else {
        Vec::new()
    };

    // remove symbols resolved via imports from undefined list
    let import_resolved: Vec<String> = import_dlls
        .iter()
        .flat_map(|dll| dll.symbols.iter().flat_map(|s| [s.export_name.clone(), s.imp_name.clone()]))
        .collect();

    // anything still undefined after import resolution is a hard error
    let still_undefined: Vec<String> = undefined
        .iter()
        .filter(|s| !import_resolved.contains(s))
        .cloned()
        .collect();

    if !still_undefined.is_empty() {
        return Err(LinkError::Coff(format!(
            "undefined symbols: {}", still_undefined.join(", ")
        )));
    }

    symtab.check_entry(&cfg.entry)?;

    // 5. merge sections by canonical name
    let mut merged: Vec<MergedSection> = Vec::new();
    let order = [".text", ".rdata", ".data", ".bss"];
    for name in &order {
        merged.push(MergedSection::new(name.to_string(), 0));
    }

    for (obj_idx, obj) in objects.iter().enumerate() {
        for (sec_idx, sec) in obj.sections.iter().enumerate() {
            let canon = canonical_name(&sec.name);
            let slot = merged.iter_mut().find(|m| m.name == canon);
            let slot = match slot {
                Some(s) => s,
                None => {
                    merged.push(MergedSection::new(canon.clone(), 0));
                    merged.last_mut().unwrap()
                }
            };
            slot.characteristics |= section_characteristics_for(sec.characteristics);
            slot.append(obj_idx, sec_idx, &sec.data);
        }
    }

    merged.retain(|m| !m.data.is_empty() || m.name == ".text");

    // 6. assign virtual addresses to merged sections
    let headers_virt = align_up(
        0x40 + 4 + 20 + 240 + (merged.len() as u32 + 1) * 40, // +1 for .idata
        SECTION_ALIGN,
    );

    let mut section_rvas: HashMap<String, u32> = HashMap::new();
    let mut current_rva = headers_virt;

    for sec in &merged {
        section_rvas.insert(sec.name.clone(), current_rva);
        current_rva = align_up(
            current_rva + align_up(sec.data.len() as u32, SECTION_ALIGN),
            SECTION_ALIGN,
        );
    }

    // 7. build .idata section at current_rva
    let idata_rva = current_rva;
    let import_table = idata::build(&import_dlls, idata_rva)?;

    // 8. compute entry point RVA
    let entry_rva = resolve_entry_rva(&cfg.entry, &objects, &symtab, &merged, &section_rvas)?;

    // 9. apply relocations
    let mut patched: Vec<Vec<u8>> = merged.iter().map(|m| m.data.clone()).collect();

    for (obj_idx, obj) in objects.iter().enumerate() {
        for (sec_idx, sec) in obj.sections.iter().enumerate() {
            let canon = canonical_name(&sec.name);
            let out_sec_idx = match merged.iter().position(|m| m.name == canon) {
                Some(i) => i,
                None => continue,
            };
            let sec_base_offset = *merged[out_sec_idx].offsets.get(&(obj_idx, sec_idx)).unwrap_or(&0);
            let section_va = section_rvas[&canon] as u64 + sec_base_offset as u64 + IMAGE_BASE;

            for reloc in &sec.relocations {
                let target_sym = obj.symbol_by_coff_index(reloc.symbol_index)
                    .ok_or_else(|| LinkError::Reloc(format!(
                        "relocation references out-of-bounds symbol index {}", reloc.symbol_index
                    )))?;

                // check if symbol is resolved via import table
                let target_va = if let Some(&iat_rva) = import_table.iat_rvas.get(&target_sym.name) {
                    iat_rva as u64 + IMAGE_BASE
                } else {
                    resolve_symbol_va(
                        target_sym,
                        obj_idx,
                        &objects,
                        &symtab,
                        &merged,
                        &section_rvas,
                    )?
                };

                let patch_offset = sec_base_offset as usize + reloc.virtual_address as usize;
                let ctx = RelocationContext {
                    section_va,
                    target_va,
                    reloc_offset: patch_offset,
                    reloc_type: reloc.reloc_type,
                };
                reloc::apply(&mut patched[out_sec_idx], &ctx)?;
            }
        }
    }

    // 10. emit PE
    // count final sections including .idata if non-empty
    let has_idata = !import_table.data.is_empty();

    let mut builder = PeBuilder::new(cfg.subsystem.clone(), entry_rva);

    // set import directory data directory entry
    if has_idata {
        builder.set_import_directory(idata_rva, import_table.data.len() as u32);
    }

    for (i, sec) in merged.iter().enumerate() {
        builder.add_section(OutputSection {
            name: sec.name.clone(),
            characteristics: sec.characteristics,
            data: patched[i].clone(),
        });
    }

    if has_idata {
        // .idata: initialized data, readable
        builder.add_section(OutputSection {
            name: ".idata".to_string(),
            characteristics: 0x40000040, // CNT_INITIALIZED_DATA | MEM_READ
            data: import_table.data,
        });
    }

    let pe_bytes = builder.build()?;
    fs::write(&cfg.output, &pe_bytes)?;

    println!("wlnk: wrote {} bytes to '{}'", pe_bytes.len(), cfg.output.display());

    Ok(())
}

fn resolve_symbol_va(
    sym: &coff::Symbol,
    obj_idx: usize,
    objects: &[coff::CoffObject],
    symtab: &SymbolTable,
    merged: &[MergedSection],
    section_rvas: &HashMap<String, u32>,
) -> Result<u64, LinkError> {
    if sym.is_defined() {
        let sec_idx = (sym.section_number - 1) as usize;
        let obj_sec = objects[obj_idx].sections.get(sec_idx)
            .ok_or_else(|| LinkError::Reloc(format!("symbol '{}' has invalid section index", sym.name)))?;
        let canon = canonical_name(&obj_sec.name);
        let merged_sec = merged.iter().find(|m| m.name == canon)
            .ok_or_else(|| LinkError::Reloc(format!("merged section '{}' not found", canon)))?;
        let base_offset = *merged_sec.offsets.get(&(obj_idx, sec_idx)).unwrap_or(&0);
        let rva = section_rvas[&canon] as u64 + base_offset as u64 + sym.value as u64;
        Ok(rva + IMAGE_BASE)
    } else {
        let resolved = symtab.map.get(&sym.name)
            .ok_or_else(|| LinkError::Reloc(format!("unresolved symbol '{}'", sym.name)))?;
        let def_obj = &objects[resolved.obj_index];
        let def_sec = &def_obj.sections[resolved.section_index];
        let canon = canonical_name(&def_sec.name);
        let merged_sec = merged.iter().find(|m| m.name == canon)
            .ok_or_else(|| LinkError::Reloc(format!(
                "merged section '{}' not found for symbol '{}'", canon, sym.name
            )))?;
        let base_offset = *merged_sec.offsets.get(&(resolved.obj_index, resolved.section_index)).unwrap_or(&0);
        let rva = section_rvas[&canon] as u64 + base_offset as u64 + resolved.offset as u64;
        Ok(rva + IMAGE_BASE)
    }
}

fn resolve_entry_rva(
    entry: &str,
    objects: &[coff::CoffObject],
    symtab: &SymbolTable,
    merged: &[MergedSection],
    section_rvas: &HashMap<String, u32>,
) -> Result<u32, LinkError> {
    let resolved = symtab.map.get(entry)
        .ok_or_else(|| LinkError::Pe(format!("entry symbol '{}' not found", entry)))?;
    let def_obj = &objects[resolved.obj_index];
    let def_sec = &def_obj.sections[resolved.section_index];
    let canon = canonical_name(&def_sec.name);
    let merged_sec = merged.iter().find(|m| m.name == canon)
        .ok_or_else(|| LinkError::Pe(format!("merged section '{}' not found", canon)))?;
    let base_offset = *merged_sec.offsets.get(&(resolved.obj_index, resolved.section_index)).unwrap_or(&0);
    Ok(section_rvas[&canon] + base_offset + resolved.offset)
}

fn canonical_name(name: &str) -> String {
    let base = name.splitn(2, '$').next().unwrap_or(name);
    match base {
        ".text" | "CODE" => ".text".to_string(),
        ".data" | "DATA" => ".data".to_string(),
        ".rdata" | ".rodata" | "CONST" => ".rdata".to_string(),
        ".bss" | "BSS" => ".bss".to_string(),
        other => other.to_string(),
    }
}

// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// parses COFF (.obj) files produced by x64 assemblers/compilers
// spec: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

use std::collections::HashMap;
use std::io::{Cursor, Read};
use crate::error::LinkError;

pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

#[derive(Debug, Clone)]
pub struct CoffHeader {
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: u32,
    pub symbol_table_offset: u32,
    pub num_symbols: u32,
    pub optional_header_size: u16,
    pub characteristics: u16,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_offset: u32,
    pub relocations_offset: u32,
    pub num_relocations: u16,
    pub characteristics: u32,
    pub data: Vec<u8>,
    pub relocations: Vec<Relocation>,
}

#[derive(Debug, Clone)]
pub struct Relocation {
    pub virtual_address: u32,
    // raw COFF symbol table index, counting auxiliary records
    pub symbol_index: u32,
    pub reloc_type: u16,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u32,
    pub section_number: i16,
    pub sym_type: u16,
    pub storage_class: u8,
    pub num_aux: u8,
}

impl Symbol {
    pub fn is_external(&self) -> bool {
        self.storage_class == 2
    }

    pub fn is_defined(&self) -> bool {
        self.section_number > 0
    }
}

#[derive(Debug)]
pub struct CoffObject {
    pub header: CoffHeader,
    pub sections: Vec<Section>,
    // flat list of non-auxiliary symbols in declaration order
    pub symbols: Vec<Symbol>,
    // maps raw COFF symbol table index -> index into self.symbols
    // needed because relocation entries reference raw indices which skip auxiliary records
    pub symbol_index_map: HashMap<u32, usize>,
}

impl CoffObject {
    // looks up a symbol by its raw COFF table index as stored in relocation entries
    pub fn symbol_by_coff_index(&self, coff_idx: u32) -> Option<&Symbol> {
        self.symbol_index_map.get(&coff_idx).map(|&i| &self.symbols[i])
    }
}

pub fn parse(data: &[u8]) -> Result<CoffObject, LinkError> {
    let mut cur = Cursor::new(data);
    let header = parse_header(&mut cur)?;

    if header.machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(LinkError::Coff(format!(
            "unsupported machine type: 0x{:04x}, expected x64 (0x8664)",
            header.machine
        )));
    }

    let sections = parse_sections(&mut cur, &header, data)?;
    let (symbols, symbol_index_map) = parse_symbols(data, &header)?;

    Ok(CoffObject { header, sections, symbols, symbol_index_map })
}

fn parse_header(cur: &mut Cursor<&[u8]>) -> Result<CoffHeader, LinkError> {
    Ok(CoffHeader {
        machine: read_u16(cur)?,
        num_sections: read_u16(cur)?,
        timestamp: read_u32(cur)?,
        symbol_table_offset: read_u32(cur)?,
        num_symbols: read_u32(cur)?,
        optional_header_size: read_u16(cur)?,
        characteristics: read_u16(cur)?,
    })
}

fn parse_sections(cur: &mut Cursor<&[u8]>, header: &CoffHeader, raw: &[u8]) -> Result<Vec<Section>, LinkError> {
    let skip = header.optional_header_size as u64;
    if skip > 0 {
        cur.set_position(cur.position() + skip);
    }

    let mut sections = Vec::with_capacity(header.num_sections as usize);

    for _ in 0..header.num_sections {
        let mut name_bytes = [0u8; 8];
        cur.read_exact(&mut name_bytes).map_err(|_| LinkError::Coff("failed to read section name".into()))?;

        let name = resolve_section_name(&name_bytes, raw, header)?;
        let virtual_size = read_u32(cur)?;
        let virtual_address = read_u32(cur)?;
        let raw_data_size = read_u32(cur)?;
        let raw_data_offset = read_u32(cur)?;
        let relocations_offset = read_u32(cur)?;
        let _line_numbers_offset = read_u32(cur)?;
        let num_relocations = read_u16(cur)?;
        let _num_line_numbers = read_u16(cur)?;
        let characteristics = read_u32(cur)?;

        let data = extract_bytes(raw, raw_data_offset as usize, raw_data_size as usize)?;
        let relocations = parse_relocations(raw, relocations_offset as usize, num_relocations as usize)?;

        sections.push(Section {
            name,
            virtual_size,
            virtual_address,
            raw_data_size,
            raw_data_offset,
            relocations_offset,
            num_relocations,
            characteristics,
            data,
            relocations,
        });
    }

    Ok(sections)
}

fn resolve_section_name(name_bytes: &[u8; 8], raw: &[u8], header: &CoffHeader) -> Result<String, LinkError> {
    if name_bytes[0] == b'/' {
        let offset_str = std::str::from_utf8(&name_bytes[1..])
            .unwrap_or("")
            .trim_end_matches('\0');
        if let Ok(offset) = offset_str.parse::<usize>() {
            let strtab_start = header.symbol_table_offset as usize + header.num_symbols as usize * 18;
            return read_string_from_table(raw, strtab_start, offset);
        }
    }
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    Ok(String::from_utf8_lossy(&name_bytes[..end]).into_owned())
}

fn parse_relocations(raw: &[u8], offset: usize, count: usize) -> Result<Vec<Relocation>, LinkError> {
    if count == 0 || offset == 0 {
        return Ok(Vec::new());
    }

    let mut relocs = Vec::with_capacity(count);
    let mut pos = offset;

    for _ in 0..count {
        if pos + 10 > raw.len() {
            return Err(LinkError::Coff("relocation entry out of bounds".into()));
        }
        let virtual_address = u32::from_le_bytes(raw[pos..pos+4].try_into().unwrap());
        let symbol_index = u32::from_le_bytes(raw[pos+4..pos+8].try_into().unwrap());
        let reloc_type = u16::from_le_bytes(raw[pos+8..pos+10].try_into().unwrap());
        relocs.push(Relocation { virtual_address, symbol_index, reloc_type });
        pos += 10;
    }

    Ok(relocs)
}

// returns (symbols vec, coff_index -> vec_index map)
// coff_index counts every 18-byte slot including auxiliaries;
// vec_index is the position of the primary record in the returned Vec
fn parse_symbols(raw: &[u8], header: &CoffHeader) -> Result<(Vec<Symbol>, HashMap<u32, usize>), LinkError> {
    if header.num_symbols == 0 {
        return Ok((Vec::new(), HashMap::new()));
    }

    let sym_offset = header.symbol_table_offset as usize;
    let strtab_start = sym_offset + header.num_symbols as usize * 18;

    let mut symbols = Vec::new();
    let mut index_map: HashMap<u32, usize> = HashMap::new();
    let mut i = 0u32;

    while i < header.num_symbols {
        let pos = sym_offset + i as usize * 18;
        if pos + 18 > raw.len() {
            return Err(LinkError::Coff("symbol entry out of bounds".into()));
        }

        let name_bytes: [u8; 8] = raw[pos..pos+8].try_into().unwrap();
        let name = resolve_symbol_name(&name_bytes, raw, strtab_start)?;
        let value = u32::from_le_bytes(raw[pos+8..pos+12].try_into().unwrap());
        let section_number = i16::from_le_bytes(raw[pos+12..pos+14].try_into().unwrap());
        let sym_type = u16::from_le_bytes(raw[pos+14..pos+16].try_into().unwrap());
        let storage_class = raw[pos+16];
        let num_aux = raw[pos+17];

        let vec_idx = symbols.len();
        // map this raw coff index to its position in the Vec
        index_map.insert(i, vec_idx);
        symbols.push(Symbol { name, value, section_number, sym_type, storage_class, num_aux });

        i += 1 + num_aux as u32;
    }

    Ok((symbols, index_map))
}

fn resolve_symbol_name(name_bytes: &[u8; 8], raw: &[u8], strtab_start: usize) -> Result<String, LinkError> {
    if name_bytes[0..4] == [0, 0, 0, 0] {
        let offset = u32::from_le_bytes(name_bytes[4..8].try_into().unwrap()) as usize;
        return read_string_from_table(raw, strtab_start, offset);
    }
    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    Ok(String::from_utf8_lossy(&name_bytes[..end]).into_owned())
}

fn read_string_from_table(raw: &[u8], strtab_start: usize, offset: usize) -> Result<String, LinkError> {
    let abs = strtab_start + offset;
    if abs >= raw.len() {
        return Err(LinkError::Coff("string table offset out of bounds".into()));
    }
    let end = raw[abs..].iter().position(|&b| b == 0).unwrap_or(raw.len() - abs);
    Ok(String::from_utf8_lossy(&raw[abs..abs+end]).into_owned())
}

fn extract_bytes(raw: &[u8], offset: usize, size: usize) -> Result<Vec<u8>, LinkError> {
    if size == 0 {
        return Ok(Vec::new());
    }
    if offset + size > raw.len() {
        return Err(LinkError::Coff("section data out of bounds".into()));
    }
    Ok(raw[offset..offset+size].to_vec())
}

fn read_u16(cur: &mut Cursor<&[u8]>) -> Result<u16, LinkError> {
    let mut buf = [0u8; 2];
    cur.read_exact(&mut buf).map_err(|_| LinkError::Coff("unexpected end of file reading u16".into()))?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(cur: &mut Cursor<&[u8]>) -> Result<u32, LinkError> {
    let mut buf = [0u8; 4];
    cur.read_exact(&mut buf).map_err(|_| LinkError::Coff("unexpected end of file reading u32".into()))?;
    Ok(u32::from_le_bytes(buf))
}

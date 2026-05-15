// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// builds a PE32+ (x64) executable from linked sections
// ref: PE/COFF spec, IMAGE_NT_HEADERS64

use crate::error::LinkError;
use crate::cli::Subsystem;

// alignment constants
pub const SECTION_ALIGN: u32 = 0x1000; // virtual alignment (4 KB pages)
pub const FILE_ALIGN: u32 = 0x200; // file alignment (512 bytes)

// preferred image base for executables
pub const IMAGE_BASE: u64 = 0x0000000140000000;

// section characteristic flags
const SCN_CNT_CODE: u32 = 0x00000020;
const SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
const SCN_MEM_EXECUTE: u32 = 0x20000000;
const SCN_MEM_READ: u32 = 0x40000000;
const SCN_MEM_WRITE: u32 = 0x80000000;

#[derive(Debug)]
pub struct OutputSection {
    pub name: String,
    pub characteristics: u32,
    pub data: Vec<u8>,
}

pub struct PeBuilder {
    pub sections: Vec<OutputSection>,
    pub entry_rva: u32,
    pub subsystem: Subsystem,
}

impl PeBuilder {
    pub fn new(subsystem: Subsystem, entry_rva: u32) -> Self {
        PeBuilder {
            sections: Vec::new(),
            entry_rva,
            subsystem,
        }
    }

    pub fn add_section(&mut self, section: OutputSection) {
        self.sections.push(section);
    }

    // serializes the complete PE file into a byte vector
    pub fn build(&self) -> Result<Vec<u8>, LinkError> {
        let num_sections = self.sections.len() as u16;

        // dos stub + pe signature + coff header + optional header + section headers
        let headers_raw_size = 0x40 // dos stub
            + 4   // "PE\0\0"
            + 20  // coff header
            + 240 // optional header (PE32+)
            + (num_sections as usize) * 40;

        let headers_file_size = align_up(headers_raw_size as u32, FILE_ALIGN);
        let headers_virt_size = align_up(headers_raw_size as u32, SECTION_ALIGN);

        // compute per-section layout
        let mut layouts: Vec<(u32, u32)> = Vec::new(); // (rva, file_offset)
        let mut current_rva = headers_virt_size;
        let mut current_file = headers_file_size;

        for sec in &self.sections {
            let rva = current_rva;
            let file_off = current_file;
            let raw_size = align_up(sec.data.len() as u32, FILE_ALIGN);
            layouts.push((rva, file_off));
            current_rva = align_up(current_rva + align_up(sec.data.len() as u32, SECTION_ALIGN), SECTION_ALIGN);
            current_file += raw_size;
        }

        let image_size = current_rva;
        let total_file_size = current_file;

        let mut out = vec![0u8; total_file_size as usize];

        write_dos_stub(&mut out);
        write_pe_signature(&mut out, 0x40);

        let coff_off = 0x40 + 4;
        write_coff_header(&mut out, coff_off, num_sections);

        let opt_off = coff_off + 20;
        write_optional_header(
            &mut out,
            opt_off,
            self.entry_rva,
            headers_virt_size,
            image_size,
            headers_file_size,
            self.subsystem.value(),
        );

        let sec_hdr_off = opt_off + 240;
        for (i, (sec, &(rva, file_off))) in self.sections.iter().zip(layouts.iter()).enumerate() {
            let raw_size = align_up(sec.data.len() as u32, FILE_ALIGN);
            let virt_size = sec.data.len() as u32;
            write_section_header(
                &mut out,
                sec_hdr_off + i * 40,
                &sec.name,
                virt_size,
                rva,
                raw_size,
                file_off,
                sec.characteristics,
            );

            let dst = &mut out[file_off as usize..file_off as usize + sec.data.len()];
            dst.copy_from_slice(&sec.data);
        }

        Ok(out)
    }
}

fn write_dos_stub(out: &mut Vec<u8>) {
    // minimal MZ header pointing PE offset at 0x40
    out[0] = b'M';
    out[1] = b'Z';
    // e_lfanew at offset 0x3c
    out[0x3c] = 0x40;
    out[0x3d] = 0x00;
    out[0x3e] = 0x00;
    out[0x3f] = 0x00;
}

fn write_pe_signature(out: &mut Vec<u8>, offset: usize) {
    out[offset] = b'P';
    out[offset+1] = b'E';
    out[offset+2] = 0;
    out[offset+3] = 0;
}

fn write_coff_header(out: &mut Vec<u8>, off: usize, num_sections: u16) {
    let machine: u16 = 0x8664;
    write_u16(out, off, machine);
    write_u16(out, off+2, num_sections);
    write_u32(out, off+4, 0); // timestamp
    write_u32(out, off+8, 0); // symbol table offset (none in output)
    write_u32(out, off+12, 0); // num symbols
    write_u16(out, off+16, 240); // optional header size (PE32+)
    write_u16(out, off+18, 0x0022); // executable, large address aware
}

fn write_optional_header(
    out: &mut Vec<u8>,
    off: usize,
    entry_rva: u32,
    headers_size: u32,
    image_size: u32,
    file_alignment: u32,
    subsystem: u16,
) {
    write_u16(out, off, 0x020B); // PE32+ magic
    out[off+2] = 14; // linker major version
    out[off+3] = 0; // linker minor version
    write_u32(out, off+4, 0); // size of code (filled later if needed)
    write_u32(out, off+8, 0); // size of initialized data
    write_u32(out, off+12, 0); // size of uninitialized data
    write_u32(out, off+16, entry_rva);
    write_u32(out, off+20, 0); // base of code
    write_u64(out, off+24, IMAGE_BASE);
    write_u32(out, off+32, SECTION_ALIGN);
    write_u32(out, off+36, file_alignment);
    write_u16(out, off+40, 6); // os major version
    write_u16(out, off+42, 0);
    write_u16(out, off+44, 0); // image major version
    write_u16(out, off+46, 0);
    write_u16(out, off+48, 6); // subsystem major version
    write_u16(out, off+50, 0);
    write_u32(out, off+52, 0); // win32 version (reserved, must be 0)
    write_u32(out, off+56, image_size);
    write_u32(out, off+60, headers_size);
    write_u32(out, off+64, 0); // checksum
    write_u16(out, off+68, subsystem);
    write_u16(out, off+70, 0x8140); // dll characteristics: dynamic base, nx compat, terminal server aware
    write_u64(out, off+72, 0x100000); // stack reserve
    write_u64(out, off+80, 0x1000); // stack commit
    write_u64(out, off+88, 0x100000); // heap reserve
    write_u64(out, off+96, 0x1000); // heap commit
    write_u32(out, off+104, 0); // loader flags (reserved)
    write_u32(out, off+108, 16); // number of data directories
    // data directories (16 x 8 bytes = 128 bytes) — all zero for now
}

fn write_section_header(
    out: &mut Vec<u8>,
    off: usize,
    name: &str,
    virtual_size: u32,
    rva: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
) {
    let mut name_bytes = [0u8; 8];
    let src = name.as_bytes();
    let copy_len = src.len().min(8);
    name_bytes[..copy_len].copy_from_slice(&src[..copy_len]);
    out[off..off+8].copy_from_slice(&name_bytes);
    write_u32(out, off+8, virtual_size);
    write_u32(out, off+12, rva);
    write_u32(out, off+16, raw_size);
    write_u32(out, off+20, raw_offset);
    write_u32(out, off+24, 0); // relocations offset (none in output)
    write_u32(out, off+28, 0); // line numbers offset
    write_u16(out, off+32, 0); // num relocations
    write_u16(out, off+34, 0); // num line numbers
    write_u32(out, off+36, characteristics);
}

pub fn align_up(val: u32, align: u32) -> u32 {
    (val + align - 1) & !(align - 1)
}

pub fn section_characteristics_for(coff_chars: u32) -> u32 {
    let mut out = 0u32;
    if coff_chars & 0x00000020 != 0 { // code
        out |= SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ;
    }
    if coff_chars & 0x00000040 != 0 { // initialized data
        out |= SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ;
    }
    if coff_chars & 0x00000080 != 0 { // uninitialized data
        out |= SCN_CNT_UNINITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE;
    }
    if coff_chars & 0x80000000 != 0 { // writable
        out |= SCN_MEM_WRITE;
    }
    if out == 0 {
        out = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ;
    }
    out
}

fn write_u16(out: &mut Vec<u8>, off: usize, val: u16) {
    out[off..off+2].copy_from_slice(&val.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, off: usize, val: u32) {
    out[off..off+4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(out: &mut Vec<u8>, off: usize, val: u64) {
    out[off..off+8].copy_from_slice(&val.to_le_bytes());
}

// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// builds a PE32+ (x64) executable from linked sections
// ref: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only

use crate::cli::Subsystem;
use crate::error::LinkError;

pub const SECTION_ALIGN: u32 = 0x1000;
pub const FILE_ALIGN: u32 = 0x200;
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
    // import directory: (rva, size), written into data directory slot 1
    import_dir: Option<(u32, u32)>,
}

impl PeBuilder {
    pub fn new(subsystem: Subsystem, entry_rva: u32) -> Self {
        PeBuilder {
            sections: Vec::new(),
            entry_rva,
            subsystem,
            import_dir: None,
        }
    }

    pub fn set_import_directory(&mut self, rva: u32, size: u32) {
        self.import_dir = Some((rva, size));
    }

    pub fn add_section(&mut self, section: OutputSection) {
        self.sections.push(section);
    }

    pub fn build(&self) -> Result<Vec<u8>, LinkError> {
        let num_sections = self.sections.len() as u16;

        let headers_raw_size = 0x40
            + 4
            + 20
            + 240
            + (num_sections as usize) * 40;

        let headers_file_size = align_up(headers_raw_size as u32, FILE_ALIGN);
        let headers_virt_size = align_up(headers_raw_size as u32, SECTION_ALIGN);

        let mut layouts: Vec<(u32, u32)> = Vec::new();
        let mut current_rva = headers_virt_size;
        let mut current_file = headers_file_size;

        for sec in &self.sections {
            layouts.push((current_rva, current_file));
            let raw_size = align_up(sec.data.len() as u32, FILE_ALIGN);
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
            self.import_dir,
        );

        let sec_hdr_off = opt_off + 240;
        for (i, (sec, &(rva, file_off))) in self.sections.iter().zip(layouts.iter()).enumerate() {
            let raw_size = align_up(sec.data.len() as u32, FILE_ALIGN);
            write_section_header(
                &mut out,
                sec_hdr_off + i * 40,
                &sec.name,
                sec.data.len() as u32,
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
    out[0] = b'M';
    out[1] = b'Z';
    // e_lfanew: offset of PE signature
    out[0x3c] = 0x40;
}

fn write_pe_signature(out: &mut Vec<u8>, offset: usize) {
    out[offset] = b'P';
    out[offset+1] = b'E';
}

fn write_coff_header(out: &mut Vec<u8>, off: usize, num_sections: u16) {
    write_u16(out, off, 0x8664); // machine: AMD64
    write_u16(out, off+2, num_sections);
    write_u32(out, off+4, 0); // timestamp
    write_u32(out, off+8, 0); // symbol table pointer (none in output)
    write_u32(out, off+12, 0); // number of symbols
    write_u16(out, off+16, 240); // optional header size
    write_u16(out, off+18, 0x0022); // characteristics: executable + large address aware
}

fn write_optional_header(
    out: &mut Vec<u8>,
    off: usize,
    entry_rva: u32,
    headers_size: u32,
    image_size: u32,
    file_alignment: u32,
    subsystem: u16,
    import_dir: Option<(u32, u32)>,
) {
    write_u16(out, off, 0x020B); // PE32+ magic
    out[off+2] = 14; // linker major version
    out[off+3] = 0;
    write_u32(out, off+4, 0); // size of code
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
    write_u32(out, off+52, 0); // win32 version (reserved)
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

    // data directory slot 1: import table
    if let Some((rva, size)) = import_dir {
        write_u32(out, off+120, rva);
        write_u32(out, off+124, size);
    }
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
    write_u32(out, off+24, 0); // relocations offset
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
    if coff_chars & 0x00000020 != 0 {
        out |= SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ;
    }
    if coff_chars & 0x00000040 != 0 {
        out |= SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ;
    }
    if coff_chars & 0x00000080 != 0 {
        out |= SCN_CNT_UNINITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE;
    }
    if coff_chars & 0x80000000 != 0 {
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

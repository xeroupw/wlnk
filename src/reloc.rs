// Copyright (c) 2026 xeroupw and Contributors. Licensed under MIT License.
// applies x64 COFF relocations to section data
// ref: PE/COFF spec table of x64 relocation types

use crate::error::LinkError;

// x64 relocation type constants
const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
const IMAGE_REL_AMD64_REL32_1: u16 = 0x0005;
const IMAGE_REL_AMD64_REL32_2: u16 = 0x0006;
const IMAGE_REL_AMD64_REL32_3: u16 = 0x0007;
const IMAGE_REL_AMD64_REL32_4: u16 = 0x0008;
const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;
const IMAGE_REL_AMD64_SECTION: u16 = 0x000A;
const IMAGE_REL_AMD64_SECREL: u16 = 0x000B;

pub struct RelocationContext {
    // virtual address of the section being patched
    pub section_va: u64,
    // virtual address of the target symbol
    pub target_va: u64,
    // byte offset of the relocation within the section
    pub reloc_offset: usize,
    pub reloc_type: u16,
}

// patches one relocation into section_data in place
pub fn apply(data: &mut Vec<u8>, ctx: &RelocationContext) -> Result<(), LinkError> {
    let off = ctx.reloc_offset;

    match ctx.reloc_type {
        IMAGE_REL_AMD64_ABSOLUTE => {
            // no-op padding relocation
        }

        IMAGE_REL_AMD64_ADDR64 => {
            // absolute 64-bit address
            check_bounds(data, off, 8)?;
            let addend = read_i64(data, off);
            let value = (ctx.target_va as i64).wrapping_add(addend);
            write_i64(data, off, value);
        }

        IMAGE_REL_AMD64_ADDR32 => {
            // absolute 32-bit address (truncated)
            check_bounds(data, off, 4)?;
            let addend = read_i32(data, off);
            let value = (ctx.target_va as i64).wrapping_add(addend as i64);
            if value < 0 || value > u32::MAX as i64 {
                return Err(LinkError::Reloc(format!(
                    "ADDR32 overflow at offset 0x{:x}: target 0x{:x}", off, ctx.target_va
                )));
            }
            write_u32(data, off, value as u32);
        }

        IMAGE_REL_AMD64_ADDR32NB => {
            // 32-bit address relative to image base (RVA), no base
            check_bounds(data, off, 4)?;
            let addend = read_i32(data, off);
            let value = (ctx.target_va as i64).wrapping_add(addend as i64);
            write_u32(data, off, value as u32);
        }

        IMAGE_REL_AMD64_REL32
        | IMAGE_REL_AMD64_REL32_1
        | IMAGE_REL_AMD64_REL32_2
        | IMAGE_REL_AMD64_REL32_3
        | IMAGE_REL_AMD64_REL32_4
        | IMAGE_REL_AMD64_REL32_5 => {
            // pc-relative 32-bit: displacement from end of instruction
            // REL32_N variants account for an extra N bytes after the reloc field
            let extra = (ctx.reloc_type - IMAGE_REL_AMD64_REL32) as i64;
            check_bounds(data, off, 4)?;
            let addend = read_i32(data, off) as i64;
            // next_ip is the address of the byte after the 4-byte field plus extra
            let next_ip = (ctx.section_va + off as u64 + 4) as i64 + extra;
            let disp = (ctx.target_va as i64).wrapping_add(addend) - next_ip;
            if disp < i32::MIN as i64 || disp > i32::MAX as i64 {
                return Err(LinkError::Reloc(format!(
                    "REL32 overflow at offset 0x{:x}: disp 0x{:x}", off, disp
                )));
            }
            write_i32(data, off, disp as i32);
        }

        IMAGE_REL_AMD64_SECTION => {
            // 16-bit section index (not yet fully supported, written as zero)
            check_bounds(data, off, 2)?;
            write_u16(data, off, 0);
        }

        IMAGE_REL_AMD64_SECREL => {
            // 32-bit offset from the start of the symbol's section
            check_bounds(data, off, 4)?;
            let addend = read_i32(data, off) as i64;
            let secrel = (ctx.target_va as i64)
                .wrapping_sub(ctx.section_va as i64)
                .wrapping_add(addend);
            write_u32(data, off, secrel as u32);
        }

        other => {
            return Err(LinkError::Reloc(format!(
                "unsupported relocation type: 0x{:04x}", other
            )));
        }
    }

    Ok(())
}

fn check_bounds(data: &[u8], offset: usize, size: usize) -> Result<(), LinkError> {
    if offset + size > data.len() {
        Err(LinkError::Reloc(format!(
            "relocation at 0x{:x} with size {} is out of section bounds (len={})",
            offset, size, data.len()
        )))
    } else {
        Ok(())
    }
}

fn read_i32(data: &[u8], off: usize) -> i32 {
    i32::from_le_bytes(data[off..off+4].try_into().unwrap())
}

fn read_i64(data: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(data[off..off+8].try_into().unwrap())
}

fn write_u32(data: &mut Vec<u8>, off: usize, val: u32) {
    data[off..off+4].copy_from_slice(&val.to_le_bytes());
}

fn write_u16(data: &mut Vec<u8>, off: usize, val: u16) {
    data[off..off+2].copy_from_slice(&val.to_le_bytes());
}

fn write_i32(data: &mut Vec<u8>, off: usize, val: i32) {
    data[off..off+4].copy_from_slice(&val.to_le_bytes());
}

fn write_i64(data: &mut Vec<u8>, off: usize, val: i64) {
    data[off..off+8].copy_from_slice(&val.to_le_bytes());
}

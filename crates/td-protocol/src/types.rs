use bitflags::bitflags;

use crate::utils;

pub type ProcessId = u32;

bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(C)]
    pub struct DriverFeature : u64 {
        const ProcessList               = 0x00_00_00_01;
        const ProcessModules            = 0x00_00_00_02;
        const ProcessProtectionKernel   = 0x00_00_00_04;

        const MemoryRead                = 0x00_00_01_00;
        const MemoryWrite               = 0x00_00_02_00;
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ProcessInfo {
    pub process_id: ProcessId,
    pub image_base_name: [u8; 0x0F],
    pub _pad: [u8; 0x01],
    pub directory_table_base: u64,
}

impl ProcessInfo {
    pub fn get_image_base_name(&self) -> Option<&str> {
        utils::fixed_buffer_to_str(&self.image_base_name)
    }

    pub fn set_image_base_name(&mut self, value: &str) -> bool {
        utils::str_to_fixed_buffer(&mut self.image_base_name, value)
    }
}

impl Default for ProcessInfo {
    fn default() -> Self {
        Self {
            process_id: 0,
            image_base_name: [0; 0x0F],
            _pad: [0; 0x01],
            directory_table_base: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ProcessModuleInfo {
    pub base_dll_name: [u8; 0x100],
    pub base_address: u64,
    pub module_size: u64,
}

impl ProcessModuleInfo {
    pub fn get_base_dll_name(&self) -> Option<&str> {
        utils::fixed_buffer_to_str(&self.base_dll_name)
    }

    pub fn set_base_dll_name(&mut self, value: &str) -> bool {
        utils::str_to_fixed_buffer(&mut self.base_dll_name, value)
    }
}

impl Default for ProcessModuleInfo {
    fn default() -> Self {
        Self {
            base_dll_name: [0; 0x100],
            base_address: 0,
            module_size: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum MemoryAccessResult {
    Success = 0,
    PartialSuccess = 1,
    ProcessUnknown = 2,
}

impl Default for MemoryAccessResult {
    fn default() -> Self {
        MemoryAccessResult::ProcessUnknown
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum DirectoryTableType {
    Default = 0,
    Explicit = 1,
}
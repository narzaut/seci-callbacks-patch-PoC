use core::ptr;

use crate::types::{
    DirectoryTableType,
    ProcessId,
    ProcessInfo,
    ProcessModuleInfo,
};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DriverCommandProcessList {
    pub buffer_capacity: usize,
    pub buffer: *mut ProcessInfo,
    pub process_count: usize,
}

impl Default for DriverCommandProcessList {
    fn default() -> Self {
        Self {
            buffer: ptr::null_mut(),
            buffer_capacity: 0,
            process_count: 0,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DriverCommandProcessModules {
    pub process_id: ProcessId,
    pub directory_table_type: DirectoryTableType,

    pub buffer_capacity: usize,
    pub buffer: *mut ProcessModuleInfo,
    pub module_count: usize,

    pub process_unknown: bool,
}

impl Default for DriverCommandProcessModules {
    fn default() -> Self {
        Self {
            process_id: 0,
            directory_table_type: DirectoryTableType::Default,

            buffer_capacity: 0,
            buffer: ptr::null_mut(),

            module_count: 0,
            process_unknown: true,
        }
    }
}
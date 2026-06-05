use core::ptr;

use crate::types::{
    DirectoryTableType,
    MemoryAccessResult,
    ProcessId,
};

pub const MAX_BATCH_READS: usize = 16;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct BatchReadSlot {
    pub address: u64,
    pub size: usize,
    pub offset_in_buffer: usize,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct DriverCommandMemoryBatchRead {
    pub process_id: ProcessId,
    pub directory_table_type: DirectoryTableType,
    pub num_requests: u32,
    pub output_buffer: *mut u8,
    pub output_buffer_size: usize,
    pub requests: [BatchReadSlot; MAX_BATCH_READS],
    pub result: MemoryAccessResult,
}

impl Default for DriverCommandMemoryBatchRead {
    fn default() -> Self {
        Self {
            process_id: 0,
            directory_table_type: DirectoryTableType::Default,
            num_requests: 0,
            output_buffer: ptr::null_mut(),
            output_buffer_size: 0,
            requests: [BatchReadSlot {
                address: 0,
                size: 0,
                offset_in_buffer: 0,
            }; MAX_BATCH_READS],
            result: MemoryAccessResult::ProcessUnknown,
        }
    }
}

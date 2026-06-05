#![no_std]

mod result;
pub use result::*;

pub mod command;
pub mod types;
pub mod utils;

pub const PROTOCOL_VERSION: u32 = 0x04;

pub type FnCommandHandler = unsafe extern "system" fn(
    command_id: u32,
    payload: *mut u8,
    payload_length: usize,
    error_message: *mut u8,
    error_message_length: usize,
) -> u64;
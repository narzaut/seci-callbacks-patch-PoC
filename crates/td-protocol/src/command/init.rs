use crate::{
    types::DriverFeature,
    utils,
};

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct VersionInfo {
    pub application_name: [u8; 0x20],
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
}

impl VersionInfo {
    pub fn get_application_name(&self) -> Option<&str> {
        utils::fixed_buffer_to_str(&self.application_name)
    }

    pub fn set_application_name(&mut self, value: &str) -> bool {
        utils::str_to_fixed_buffer(&mut self.application_name, value)
    }
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct DriverCommandInitialize {
    pub client_protocol_version: u32,

    pub driver_protocol_version: u32,

    pub result: u32,

    pub client_version: VersionInfo,

    pub driver_version: VersionInfo,

    pub driver_features: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum InitializeResult {
    Success = 1,
    Unavailable = 0,
}

impl Default for InitializeResult {
    fn default() -> Self {
        Self::Unavailable
    }
}
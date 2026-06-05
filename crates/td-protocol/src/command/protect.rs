#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum ProcessProtectionMode {
    None = 0,
    Kernel = 1,
}

impl Default for ProcessProtectionMode {
    fn default() -> Self {
        ProcessProtectionMode::None
    }
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct DriverCommandProcessProtection {
    pub mode: ProcessProtectionMode,
}
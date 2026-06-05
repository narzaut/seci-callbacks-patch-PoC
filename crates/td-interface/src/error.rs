use thiserror::Error;

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("failed to find any memory driver")]
    NoDriverFound,

    #[error("protocol mismatch (expected {interface_protocol} but driver supports {driver_protocol})")]
    DriverProtocolMismatch {
        interface_protocol: u32,
        driver_protocol: u32,
    },

    #[error("command failed: {message}")]
    CommandGenericError { message: String },

    #[error("feature is not supported")]
    FeatureUnsupported,

    #[error("the driver is unavailable")]
    InitializeDriverUnavailable,

    #[error("process unknown")]
    ProcessUnknown,

    #[error("failed to access memory")]
    MemoryAccessFailed,

    #[error("failed to allocate a properly sized buffer")]
    BufferAllocationFailed,
}

pub type IResult<T> = std::result::Result<T, InterfaceError>;
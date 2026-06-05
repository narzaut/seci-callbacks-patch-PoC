use core::{
    mem,
    sync::atomic::{
        AtomicUsize,
        Ordering,
    },
};

use td_protocol::{
    command::{
        DriverCommand,
        DriverCommandInitialize,
        DriverCommandMemoryBatchRead,
        DriverCommandMemoryRead,
        DriverCommandMemoryWrite,
        DriverCommandProcessList,
        DriverCommandProcessModules,
        InitializeResult,
        VersionInfo,
        MAX_BATCH_READS,
    },
    types::{
        DirectoryTableType,
        DriverFeature,
        MemoryAccessResult,
        ProcessId,
        ProcessInfo,
        ProcessModuleInfo,
    },
    CommandResult,
    PROTOCOL_VERSION,
};

use crate::{
    IResult,
    InterfaceError,
};

pub struct DriverInterface {
    handle: windows::Win32::Foundation::HANDLE,
    driver_version: VersionInfo,
    driver_features: DriverFeature,
    read_calls: AtomicUsize,
}

impl DriverInterface {
    pub fn from_handle(handle: windows::Win32::Foundation::HANDLE) -> IResult<Self> {
        let mut interface = Self {
            handle,
            driver_version: VersionInfo::default(),
            driver_features: DriverFeature::empty(),
            read_calls: AtomicUsize::new(0),
        };
        interface.initialize()?;
        Ok(interface)
    }

    fn execute_command<C: DriverCommand>(&self, command: &mut C) -> IResult<String> {
        let mut error_buffer = vec![0u8; 0x500];

        let control_code = {
            (0x00000022u32 << 16)
                | (0x00000000u32 << 14)
                | (0x00000001u32 << 13)
                | ((C::COMMAND_ID & 0x3F) << 2)
                | 0x00000003u32
        };

        let command_buffer = unsafe {
            core::slice::from_raw_parts_mut(
                command as *mut C as *mut u8,
                mem::size_of::<C>(),
            )
        };

        let mut bytes_returned = 0u32;
        let _success = unsafe {
            windows::Win32::System::IO::DeviceIoControl(
                self.handle,
                control_code,
                Some(command_buffer.as_ptr() as *const core::ffi::c_void),
                command_buffer.len() as u32,
                Some(command_buffer.as_mut_ptr() as *mut core::ffi::c_void),
                command_buffer.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        let result = CommandResult::from_bits_retain(unsafe { *(command_buffer.as_ptr() as *const u64) });

        let error_length = error_buffer.iter().position(|v| *v == 0).unwrap_or(error_buffer.len());
        error_buffer.truncate(error_length);
        let error = String::from_utf8_lossy(&error_buffer);

        match result {
            CommandResult::Success => return Ok(error.to_string()),
            CommandResult::Error => Err(InterfaceError::CommandGenericError { message: error.to_string() }),
            CommandResult::CommandParameterInvalid => Err(InterfaceError::CommandGenericError { message: format!("parameter invalid: {}", error) }),
            CommandResult::CommandInvalid => Err(InterfaceError::CommandGenericError { message: "command invalid".to_string() }),
            CommandResult::CommandFeatureUnsupported => Err(InterfaceError::FeatureUnsupported),
            _ => Err(InterfaceError::CommandGenericError { message: "invalid command result".to_string() }),
        }
    }

    fn initialize(&mut self) -> IResult<()> {
        let mut command = DriverCommandInitialize::default();
        command.client_protocol_version = PROTOCOL_VERSION;
        command.client_version = {
            let mut version_info = VersionInfo::default();
            version_info.set_application_name("td-interface");
            version_info.version_major = 0;
            version_info.version_minor = 1;
            version_info.version_patch = 0;
            version_info
        };

        self.execute_command(&mut command)?;
        if command.client_protocol_version != command.driver_protocol_version {
            return Err(InterfaceError::DriverProtocolMismatch {
                interface_protocol: command.client_protocol_version,
                driver_protocol: command.driver_protocol_version,
            });
        }

        match command.result {
            InitializeResult::Success => {}
            InitializeResult::Unavailable => {
                return Err(InterfaceError::InitializeDriverUnavailable);
            }
        };

        self.driver_version = command.driver_version;
        self.driver_features = command.driver_features;
        Ok(())
    }

    pub fn driver_version(&self) -> &VersionInfo {
        &self.driver_version
    }

    pub fn driver_features(&self) -> DriverFeature {
        self.driver_features
    }

    pub fn read_slice(
        &self,
        process_id: ProcessId,
        address: u64,
        buffer: &mut [u8],
    ) -> IResult<()> {
        self.read_calls.fetch_add(1, Ordering::Relaxed);

        let mut command = DriverCommandMemoryRead::default();
        command.process_id = process_id;
        command.directory_table_type = DirectoryTableType::Default;
        command.address = address;
        command.buffer = buffer.as_mut_ptr();
        command.count = buffer.len();

        self.execute_command(&mut command)?;
        match command.result {
            MemoryAccessResult::Success => Ok(()),
            MemoryAccessResult::ProcessUnknown => Err(InterfaceError::ProcessUnknown),
            MemoryAccessResult::PartialSuccess => Err(InterfaceError::MemoryAccessFailed),
        }
    }

    pub fn read<T: Copy + Default>(&self, process_id: ProcessId, address: u64) -> IResult<T> {
        let mut result: T = Default::default();
        let size = mem::size_of::<T>();
        self.read_slice(process_id, address, unsafe {
            core::slice::from_raw_parts_mut(&mut result as *mut T as *mut u8, size)
        })?;
        Ok(result)
    }

    pub fn batch_read(
        &self,
        process_id: ProcessId,
        requests: &[(u64, usize)],
        output: &mut [u8],
    ) -> IResult<()> {
        if requests.is_empty() || requests.len() > MAX_BATCH_READS {
            return Err(InterfaceError::CommandGenericError {
                message: format!("invalid batch request count: {}", requests.len()),
            });
        }

        self.read_calls.fetch_add(requests.len(), Ordering::Relaxed);

        let mut command = DriverCommandMemoryBatchRead::default();
        command.process_id = process_id;
        command.num_requests = requests.len() as u32;
        command.output_buffer = output.as_mut_ptr();
        command.output_buffer_size = output.len();

        let mut offset = 0usize;
        for (i, (addr, size)) in requests.iter().enumerate() {
            if offset + size > output.len() {
                return Err(InterfaceError::CommandGenericError {
                    message: format!("batch read output buffer overflow"),
                });
            }
            command.requests[i] = td_protocol::command::BatchReadSlot {
                address: *addr,
                size: *size,
                offset_in_buffer: offset,
            };
            offset += size;
        }

        self.execute_command(&mut command)?;
        match command.result {
            MemoryAccessResult::Success => Ok(()),
            MemoryAccessResult::ProcessUnknown => Err(InterfaceError::ProcessUnknown),
            MemoryAccessResult::PartialSuccess => Err(InterfaceError::MemoryAccessFailed),
        }
    }

    pub fn write_slice(
        &self,
        process_id: ProcessId,
        address: u64,
        buffer: &[u8],
    ) -> IResult<()> {
        let mut command = DriverCommandMemoryWrite::default();
        command.process_id = process_id;
        command.directory_table_type = DirectoryTableType::Default;
        command.address = address;
        command.buffer = buffer.as_ptr();
        command.count = buffer.len();

        self.execute_command(&mut command)?;
        match command.result {
            MemoryAccessResult::Success => Ok(()),
            MemoryAccessResult::ProcessUnknown => Err(InterfaceError::ProcessUnknown),
            MemoryAccessResult::PartialSuccess => Err(InterfaceError::MemoryAccessFailed),
        }
    }

    pub fn list_processes(&self) -> IResult<Vec<ProcessInfo>> {
        let mut buffer = vec![ProcessInfo::default(); 4096];

        let mut command = DriverCommandProcessList::default();
        command.buffer = buffer.as_mut_ptr();
        command.buffer_capacity = buffer.len();
        command.process_count = 0;

        self.execute_command(&mut command)?;
        buffer.truncate(command.process_count);
        Ok(buffer)
    }

    pub fn list_modules(&self, process_id: ProcessId) -> IResult<Vec<ProcessModuleInfo>> {
        let mut buffer = vec![ProcessModuleInfo::default(); 512];

        let mut command = DriverCommandProcessModules::default();
        command.process_id = process_id;
        command.directory_table_type = DirectoryTableType::Default;
        command.buffer = buffer.as_mut_ptr();
        command.buffer_capacity = buffer.len();
        command.module_count = 0;

        self.execute_command(&mut command)?;
        if command.process_unknown {
            return Err(InterfaceError::ProcessUnknown);
        }
        buffer.truncate(command.module_count);
        Ok(buffer)
    }
}
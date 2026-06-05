mod init;
pub use init::*;

mod memory_read;
pub use memory_read::*;

mod memory_write;
pub use memory_write::*;

mod memory_batch_read;
pub use memory_batch_read::*;

mod process;
pub use process::*;

mod protect;
pub use protect::*;

pub trait DriverCommand: Default + Copy {
    const COMMAND_ID: u32;
}

macro_rules! define_command {
    ($struct:ty, $id:expr) => {
        impl DriverCommand for $struct {
            const COMMAND_ID: u32 = $id;
        }
    };
}

define_command!(DriverCommandInitialize, 0x00);
define_command!(DriverCommandProcessList, 0x01);
define_command!(DriverCommandProcessModules, 0x02);
define_command!(DriverCommandMemoryRead, 0x03);
define_command!(DriverCommandMemoryWrite, 0x04);
define_command!(DriverCommandProcessProtection, 0x05);
define_command!(DriverCommandMemoryBatchRead, 0x06);
define_command!(DriverCommandTriggerClick, 0x07);

mod trigger_click;
pub use trigger_click::*;
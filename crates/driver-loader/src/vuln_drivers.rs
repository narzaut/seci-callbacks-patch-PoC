// VulnDriver trait — abstraction for any kernel driver backend.
//
// Implement this trait to add support for a specific driver.
// See the README and poc/ directory for usage examples.

use crate::cleanup;
use anyhow::Result;
use std::path::PathBuf;

pub trait VulnDriver: Send + Sync {
    fn name(&self) -> &str;
    fn device_path(&self) -> &str;
    fn service_name(&self) -> &str;
    fn driver_filename(&self) -> &str;
    fn driver_file_path(&self) -> &PathBuf;

    fn install_service(&self, bin_path: &PathBuf) -> Result<()> {
        cleanup::install_service(self.service_name(), bin_path, self.driver_filename())
    }
    fn start_service(&self) -> Result<()> {
        cleanup::start_service(self.service_name())
    }
    fn stop_service(&self) -> Result<()> {
        cleanup::stop_service(self.service_name())
    }
    fn delete_service(&self) -> Result<()> {
        cleanup::delete_service(self.service_name())
    }
    fn open_device(&self) -> Result<*mut core::ffi::c_void>;

    fn is_virtual_mode(&self) -> bool;
    fn needs_cr3_scan(&self) -> bool { true }

    fn raw_read_u32(&self, dev: *mut core::ffi::c_void, addr: u64) -> Result<u32>;
    fn raw_write_u32(&self, dev: *mut core::ffi::c_void, addr: u64, value: u32) -> Result<()>;

    unsafe fn raw_read(&self, dev: *mut core::ffi::c_void, addr: u64, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset + 4 <= buf.len() {
            let val = self.raw_read_u32(dev, addr + offset as u64)?;
            buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
            offset += 4;
        }
        Ok(())
    }

    unsafe fn raw_write(&self, dev: *mut core::ffi::c_void, addr: u64, buf: &[u8]) -> Result<()> {
        let mut offset = 0usize;
        while offset + 4 <= buf.len() {
            let val = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
            self.raw_write_u32(dev, addr + offset as u64, val)?;
            offset += 4;
        }
        Ok(())
    }

    unsafe fn raw_read_u64(&self, dev: *mut core::ffi::c_void, addr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.raw_read(dev, addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    unsafe fn raw_write_u64(&self, dev: *mut core::ffi::c_void, addr: u64, value: u64) -> Result<()> {
        self.raw_write(dev, addr, &value.to_le_bytes())
    }

    fn virt_to_phys(&self, dev: *mut core::ffi::c_void, cr3: u64, virt_addr: u64) -> Result<u64>;

    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;

    unsafe fn read_virtual_u32(&self, dev: *mut core::ffi::c_void, cr3: u64, virt_addr: u64) -> Result<u32> {
        if self.is_virtual_mode() {
            self.raw_read_u32(dev, virt_addr)
        } else {
            let phys = self.virt_to_phys(dev, cr3, virt_addr)?;
            self.raw_read_u32(dev, phys)
        }
    }

    unsafe fn read_virtual_u64(&self, dev: *mut core::ffi::c_void, cr3: u64, virt_addr: u64) -> Result<u64> {
        if self.is_virtual_mode() {
            self.raw_read_u64(dev, virt_addr)
        } else {
            let phys = self.virt_to_phys(dev, cr3, virt_addr)?;
            self.raw_read_u64(dev, phys)
        }
    }

    unsafe fn write_virtual_u64(&self, dev: *mut core::ffi::c_void, cr3: u64, addr: u64, value: u64) -> Result<()> {
        self.write_virtual(dev, cr3, addr, &value.to_le_bytes())
    }

    unsafe fn write_virtual(&self, dev: *mut core::ffi::c_void, cr3: u64, virt_addr: u64, data: &[u8]) -> Result<()> {
        if self.is_virtual_mode() {
            let mut offset = 0usize;
            while offset + 4 <= data.len() {
                let val = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                self.raw_write_u32(dev, virt_addr + offset as u64, val)?;
                offset += 4;
            }
            if offset < data.len() {
                let remaining = data.len() - offset;
                let existing = self.raw_read_u32(dev, virt_addr + offset as u64)?;
                let mut bytes = existing.to_le_bytes();
                bytes[..remaining].copy_from_slice(&data[offset..]);
                self.raw_write_u32(dev, virt_addr + offset as u64, u32::from_le_bytes(bytes))?;
            }
            Ok(())
        } else {
            let mut offset = 0usize;
            while offset < data.len() {
                let remaining = data.len() - offset;
                let virt = virt_addr + offset as u64;
                let phys = self.virt_to_phys(dev, cr3, virt)?;

                let write_size = remaining.min(0x1000 - (virt as usize & 0xFFF));
                if write_size >= 4 {
                    let aligned_size = write_size & !3;
                    self.raw_write(dev, phys, &data[offset..offset + aligned_size])?;
                } else {
                    let val = u32::from_le_bytes({
                        let mut arr = [0u8; 4];
                        arr[..remaining].copy_from_slice(&data[offset..offset + remaining]);
                        arr
                    });
                    self.raw_write_u32(dev, phys, val)?;
                }
                offset += write_size;
            }
            Ok(())
        }
    }

    unsafe fn read_virtual(&self, dev: *mut core::ffi::c_void, cr3: u64, virt_addr: u64, buf: &mut [u8]) -> Result<()> {
        if self.is_virtual_mode() {
            let mut offset = 0usize;
            while offset + 4 <= buf.len() {
                let val = self.raw_read_u32(dev, virt_addr + offset as u64)?;
                buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
                offset += 4;
            }
            if offset < buf.len() {
                let remaining = buf.len() - offset;
                let val = self.raw_read_u32(dev, virt_addr + offset as u64)?;
                buf[offset..offset + remaining].copy_from_slice(&val.to_le_bytes()[..remaining]);
            }
            Ok(())
        } else {
            let mut offset = 0usize;
            while offset < buf.len() {
                let remaining = buf.len() - offset;
                let virt = virt_addr + offset as u64;
                let phys = self.virt_to_phys(dev, cr3, virt)?;

                let read_size = remaining.min(0x1000 - (virt as usize & 0xFFF));
                if read_size >= 4 {
                    let aligned_size = read_size & !3;
                    self.raw_read(dev, phys, &mut buf[offset..offset + aligned_size])?;
                } else {
                    let val = self.raw_read_u32(dev, phys)?;
                    buf[offset..offset + remaining].copy_from_slice(&val.to_le_bytes()[..remaining]);
                }
                offset += read_size;
            }
            Ok(())
        }
    }

    }
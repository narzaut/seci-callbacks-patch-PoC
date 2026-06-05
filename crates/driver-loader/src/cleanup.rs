use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub fn install_service(service_name: &str, driver_path: &PathBuf) -> Result<()> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Services::*;
        use windows::core::HSTRING;

        let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) }
            .context("failed to open service control manager")?;

        let service_name_w = HSTRING::from(service_name);
        let driver_path_w = HSTRING::from(driver_path.to_string_lossy().as_ref());

        let service = unsafe {
            CreateServiceW(
                scm,
                &service_name_w,
                &service_name_w,
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                &driver_path_w,
                None,
                None,
                None,
                None,
                None,
            )
        };

        match service {
            Ok(s) => {
                log::info!("installed service '{}'", service_name);
                unsafe { CloseServiceHandle(s) };
            }
            Err(e) if e.code().0 == 0x80070431u32 as i32 => {
                // Service already exists — delete and recreate with new binary path
                log::info!("service '{}' already exists, recreating", service_name);
                let old = unsafe { OpenServiceW(scm, &service_name_w, SERVICE_ALL_ACCESS) };
                if let Ok(old_svc) = old {
                    let mut ss = SERVICE_STATUS::default();
                    unsafe { ControlService(old_svc, SERVICE_CONTROL_STOP, &mut ss) }.ok();
                    unsafe { DeleteService(old_svc).ok() };
                    unsafe { CloseServiceHandle(old_svc) };
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                let new_svc = unsafe {
                    CreateServiceW(scm, &service_name_w, &service_name_w,
                        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                        SERVICE_ERROR_IGNORE, &driver_path_w,
                        None, None, None, None, None)
                };
                match new_svc {
                    Ok(s) => {
                        log::info!("reinstalled service '{}'", service_name);
                        unsafe { CloseServiceHandle(s) };
                    }
                    Err(e2) => bail!("failed to recreate service '{}': {}", service_name, e2),
                }
            }
            Err(e) => {
                bail!("failed to create service '{}': {}", service_name, e);
            }
        }

        unsafe { CloseServiceHandle(scm) };
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (service_name, driver_path);
        bail!("service management only supported on Windows");
    }
}

pub fn start_service(service_name: &str) -> Result<()> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Services::*;
        use windows::core::HSTRING;

        let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) }
            .context("failed to open service control manager")?;

        let service_name_w = HSTRING::from(service_name);
        let service = unsafe { OpenServiceW(scm, &service_name_w, SERVICE_ALL_ACCESS) }
            .context(format!("failed to open service '{}'", service_name))?;

        let result = unsafe { StartServiceW(service, None) };
        match result {
            Ok(()) => log::info!("started service '{}'", service_name),
            Err(e) if e.code().0 == 0x80070420u32 as i32 => {
                log::info!("service '{}' already running", service_name);
            }
            Err(e) => {
                bail!("failed to start service '{}': {}", service_name, e);
            }
        }

        unsafe { CloseServiceHandle(service) };
        unsafe { CloseServiceHandle(scm) };
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = service_name;
        bail!("service management only supported on Windows");
    }
}

pub fn stop_service(service_name: &str) -> Result<()> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Services::*;
        use windows::core::HSTRING;

        let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) }
            .context("failed to open service control manager")?;

        let service_name_w = HSTRING::from(service_name);
        let service = match unsafe { OpenServiceW(scm, &service_name_w, SERVICE_ALL_ACCESS) } {
            Ok(s) => s,
            Err(_) => {
                log::info!("service '{}' not found (already removed)", service_name);
                unsafe { CloseServiceHandle(scm) };
                return Ok(());
            }
        };

        let mut status = SERVICE_STATUS::default();
        unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) }.ok();

        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            unsafe { QueryServiceStatus(service, &mut status) }.ok();
            if status.dwCurrentState == SERVICE_STOPPED {
                break;
            }
        }

        log::info!("stopped service '{}'", service_name);
        unsafe { CloseServiceHandle(service) };
        unsafe { CloseServiceHandle(scm) };
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = service_name;
        bail!("service management only supported on Windows");
    }
}

pub fn delete_service(service_name: &str) -> Result<()> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Services::*;
        use windows::core::HSTRING;

        let scm = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) }
            .context("failed to open service control manager")?;

        let service_name_w = HSTRING::from(service_name);
        let service = match unsafe { OpenServiceW(scm, &service_name_w, SERVICE_ALL_ACCESS) } {
            Ok(s) => s,
            Err(_) => {
                log::info!("service '{}' not found (already removed)", service_name);
                unsafe { CloseServiceHandle(scm) };
                return Ok(());
            }
        };

        unsafe { DeleteService(service) }.ok();
        log::info!("deleted service '{}'", service_name);
        unsafe { CloseServiceHandle(service) };
        unsafe { CloseServiceHandle(scm) };
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = service_name;
        bail!("service management only supported on Windows");
    }
}

pub fn secure_delete_file(path: &PathBuf) -> Result<()> {
    if !path.exists() {
        log::info!("file '{}' not found (already removed)", path.display());
        return Ok(());
    }

    #[cfg(windows)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;

        let size = std::fs::metadata(path)?.len();
        let zeros = vec![0u8; size as usize];

        let mut file = OpenOptions::new().write(true).open(path)?;
        file.write_all(&zeros)?;
        file.sync_all()?;
        drop(file);

        std::fs::remove_file(path)?;
        log::info!("securely deleted '{}'", path.display());
        Ok(())
    }
    #[cfg(not(windows))]
    {
        bail!("file operations only supported on Windows");
    }
}
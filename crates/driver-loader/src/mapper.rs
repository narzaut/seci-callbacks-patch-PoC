use crate::cleanup;
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub struct Mapper {
    pub driver_path: PathBuf,
    pub service_name: String,
}

impl Mapper {
    pub fn new(driver_path: PathBuf, service_name: &str) -> Result<Self> {
        if !driver_path.exists() {
            bail!("driver file not found: {}", driver_path.display());
        }
        Ok(Self {
            driver_path,
            service_name: service_name.to_string(),
        })
    }

    pub fn install_and_start(&mut self) -> Result<()> {
        let driver_filename = self.driver_path
            .file_name()
            .context("invalid driver filename")?
            .to_string_lossy()
            .to_string();

        log::info!("Installing driver service '{}'...", self.service_name);
        cleanup::install_service(&self.service_name, &self.driver_path, &driver_filename)?;

        log::info!("Starting driver service '{}'...", self.service_name);
        cleanup::start_service(&self.service_name)?;
        Ok(())
    }

    pub fn stop_and_delete(&mut self) -> Result<()> {
        log::info!("Stopping driver service '{}'...", self.service_name);
        let _ = cleanup::stop_service(&self.service_name);

        log::info!("Deleting driver service '{}'...", self.service_name);
        cleanup::delete_service(&self.service_name)?;
        Ok(())
    }

    pub fn wipe_driver_file(&self) -> Result<()> {
        cleanup::secure_delete_file(&self.driver_path)
    }
}

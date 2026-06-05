//! driver-loader — Kernel driver lifecycle management via SCM.
//!
//! Loads a driver using the Windows Service Control Manager.
//! Designed to work after DSE has been bypassed (see the `poc/` directory).
//!
//! Usage:
//!   driver-loader load <driver.sys> [--service-name <name>]
//!   driver-loader unload <service-name>

mod cleanup;
mod mapper;
mod pe;
mod vuln_drivers;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use mapper::Mapper;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "driver-loader", about = "Kernel driver lifecycle management")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load a kernel driver via the Service Control Manager
    Load {
        /// Path to the .sys driver file
        driver: PathBuf,

        /// Service name (defaults to the driver filename without extension)
        #[arg(short, long)]
        service_name: Option<String>,
    },
    /// Stop and delete a kernel driver service
    Unload {
        /// Service name to stop and delete
        service_name: String,
    },
}

fn run() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_target(false)
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Load { driver, service_name } => {
            let svc = service_name.unwrap_or_else(|| {
                driver.file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown-driver".to_string())
            });

            let mut mapper = Mapper::new(driver.clone(), &svc)?;
            mapper.install_and_start()?;
            log::info!("Driver '{}' loaded as service '{}'", driver.display(), svc);
        }

        Command::Unload { service_name } => {
            let mut mapper = Mapper::new(PathBuf::from("unused.sys"), &service_name)?;
            mapper.stop_and_delete()?;
            log::info!("Driver service '{}' unloaded successfully", service_name);
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {:#}", e);
        std::process::exit(1);
    }
}

#![forbid(unsafe_code)]

use std::env;
use std::io;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use install_appimage::adapters::inbound::cli::{
    CliArgs, CliDispatcher, try_render_static_cli_output,
};
use install_appimage::adapters::outbound::appimage_extractor::StaticAppImageExtractor;
use install_appimage::adapters::outbound::desktop_cache::HostDesktopCacheAdapter;
use install_appimage::adapters::outbound::json_registry::JsonRegistryAdapter;
use install_appimage::adapters::outbound::system_probe::{ArchSystemProbeAdapter, SystemClock};
use install_appimage::adapters::outbound::xdg_fs::XdgFileSystemAdapter;
use install_appimage::domain::models::XdgLayout;
use install_appimage::domain::sanitizer::sanitize_for_error;

fn main() -> Result<()> {
    let args = CliArgs::parse();
    let mut stdout = io::stdout().lock();

    if try_render_static_cli_output(&args, &mut stdout)
        .map_err(|err| anyhow::Error::msg(sanitize_for_error(&err.sanitized().to_string())))?
    {
        return Ok(());
    }

    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .context("HOME environment variable is not set")?;
    let xdg_data_home = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    let layout = XdgLayout::try_from_env_values(&home, xdg_data_home.as_deref())
        .map_err(|err| anyhow::Error::msg(sanitize_for_error(&err.sanitized().to_string())))?;

    let extractor = StaticAppImageExtractor;
    let fs = XdgFileSystemAdapter;
    let registry = JsonRegistryAdapter::new(&fs);
    let desktop_cache = HostDesktopCacheAdapter;
    let system_probe = ArchSystemProbeAdapter;
    let clock = SystemClock;

    let dispatcher = CliDispatcher::new(
        &extractor,
        &fs,
        &registry,
        &desktop_cache,
        &system_probe,
        &clock,
    );

    let mut stderr = io::stderr().lock();
    dispatcher
        .dispatch(args, &layout, &mut stdout, &mut stderr)
        .map_err(|err| anyhow::Error::msg(sanitize_for_error(&err.sanitized().to_string())))?;

    Ok(())
}

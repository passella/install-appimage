use std::path::{Path, PathBuf};

use crate::domain::error::DomainError;
use crate::domain::models::{
    CacheRefreshOutcome, DoctorReport, InspectedAppImage, InstalledApp, XdgLayout,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedFileHashProbe {
    Hashed(String),
    Missing,
    NotRegularFile(String),
    UnsafePath(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedArtifactProbe {
    Ok,
    Missing,
    Invalid(String),
    UnsafePath(String),
}

pub trait AppImageExtractorPort {
    fn inspect_and_extract(
        &self,
        appimage_path: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<InspectedAppImage, DomainError>;
}

pub trait FileSystemPort {
    fn path_or_symlink_exists(&self, path: &Path) -> bool;
    fn is_regular_non_symlink_file(&self, path: &Path) -> bool;
    fn hash_managed_regular_file(
        &self,
        root: &Path,
        path: &Path,
    ) -> Result<ManagedFileHashProbe, DomainError>;
    fn verify_managed_regular_file(
        &self,
        root: &Path,
        path: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<ManagedArtifactProbe, DomainError>;
    fn verify_managed_symlink(
        &self,
        root: &Path,
        link_path: &Path,
        allowed_targets: &[&Path],
    ) -> Result<ManagedArtifactProbe, DomainError>;
    fn same_file(&self, left: &Path, right: &Path) -> Result<bool, DomainError>;
    fn ensure_symlink_free_path(&self, root: &Path, target: &Path) -> Result<(), DomainError>;
    fn create_dir_all_safe(
        &self,
        root: &Path,
        path: &Path,
        dry_run: bool,
    ) -> Result<(), DomainError>;
    fn install_executable_verified(
        &self,
        src: &Path,
        dst: &Path,
        expected_sha256: &str,
        move_source: bool,
        dry_run: bool,
    ) -> Result<(), DomainError>;
    fn write_file_atomic(
        &self,
        root: &Path,
        path: &Path,
        contents: &[u8],
        mode: u32,
        dry_run: bool,
    ) -> Result<(), DomainError>;
    fn create_symlink_atomic(
        &self,
        root: &Path,
        target: &Path,
        link_path: &Path,
        dry_run: bool,
    ) -> Result<(), DomainError>;
    fn remove_file_if_exists(
        &self,
        root: &Path,
        path: &Path,
        dry_run: bool,
    ) -> Result<bool, DomainError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedRegistry {
    pub schema_version: Option<u32>,
    pub apps: Vec<InstalledApp>,
}

pub trait RegistryPort {
    fn load(&self, layout: &XdgLayout) -> Result<Vec<InstalledApp>, DomainError>;
    fn load_with_meta(&self, layout: &XdgLayout) -> Result<LoadedRegistry, DomainError> {
        Ok(LoadedRegistry {
            schema_version: None,
            apps: self.load(layout)?,
        })
    }
    fn save(
        &self,
        layout: &XdgLayout,
        apps: &[InstalledApp],
        dry_run: bool,
    ) -> Result<(), DomainError>;
}

pub trait DesktopCachePort {
    fn validate_desktop_file(&self, desktop_path: &Path) -> Vec<String>;
    fn refresh_desktop_caches(&self, layout: &XdgLayout, dry_run: bool)
    -> Vec<CacheRefreshOutcome>;
}

pub trait SystemProbePort {
    fn probe_environment(&self, layout: &XdgLayout) -> DoctorReport;
}

pub trait ClockPort {
    fn utc_timestamp_iso8601(&self) -> String;
}

pub fn collect_owned_paths(app: &InstalledApp) -> Vec<PathBuf> {
    let mut paths = Vec::with_capacity(4 + app.icon_paths.len());
    paths.push(app.appimage_path.clone());
    if let Some(ref link) = app.stable_symlink_path {
        paths.push(link.clone());
    }
    if let Some(ref cli) = app.cli_symlink_path {
        paths.push(cli.clone());
    }
    paths.push(app.desktop_file_path.clone());
    paths.extend(app.icon_paths.iter().cloned());
    paths
}

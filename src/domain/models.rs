use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use crate::domain::error::DomainError;
use crate::domain::sanitizer::is_bidi_or_invisible_format;
use crate::domain::slug::AppSlug;

pub const STANDARD_ICON_BUCKETS: [u32; 13] =
    [16, 22, 24, 32, 36, 48, 64, 72, 96, 128, 192, 256, 512];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconFormat {
    Png,
    Svg,
}

impl IconFormat {
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Svg => "svg",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedIcon {
    pub size_dir: String,
    pub format: IconFormat,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopFieldCode {
    LowerF,
    UpperF,
    LowerU,
    UpperU,
}

impl DesktopFieldCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LowerF => "%f",
            Self::UpperF => "%F",
            Self::LowerU => "%u",
            Self::UpperU => "%U",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedMetadata {
    pub app_name: String,
    pub version: Option<String>,
    pub generic_name: Option<String>,
    pub comment: Option<String>,
    pub icon_key: Option<String>,
    pub categories: Vec<String>,
    pub mime_types: Vec<String>,
    pub keywords: Vec<String>,
    pub startup_wm_class: Option<String>,
    pub terminal: bool,
    pub startup_notify: Option<bool>,
    pub exec_field_code: Option<DesktopFieldCode>,
    pub icons: Vec<ExtractedIcon>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedAppImage {
    pub metadata: ExtractedMetadata,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdgLayout {
    pub applications_dir: PathBuf,
    pub bin_dir: PathBuf,
    pub desktop_entries_dir: PathBuf,
    pub icons_hicolor_dir: PathBuf,
    pub registry_path: PathBuf,
}

impl XdgLayout {
    pub fn try_from_env_values(
        home: &Path,
        xdg_data_home: Option<&Path>,
    ) -> Result<Self, DomainError> {
        let normalized_home = validate_env_dir_path(home, "HOME")?;

        let data_home = match xdg_data_home {
            Some(path) if !path.as_os_str().is_empty() => {
                validate_env_dir_path(path, "XDG_DATA_HOME")?
            }
            _ => normalized_home.join(".local").join("share"),
        };

        Ok(Self {
            applications_dir: normalized_home.join("Applications"),
            bin_dir: normalized_home.join(".local").join("bin"),
            desktop_entries_dir: data_home.join("applications"),
            icons_hicolor_dir: data_home.join("icons").join("hicolor"),
            registry_path: data_home.join("install-appimage").join("registry.json"),
        })
    }

    pub fn managed_roots(&self) -> [&Path; 4] {
        [
            self.applications_dir.as_path(),
            self.bin_dir.as_path(),
            self.desktop_entries_dir.as_path(),
            self.icons_hicolor_dir.as_path(),
        ]
    }
}

fn validate_env_dir_path(path: &Path, var_name: &str) -> Result<PathBuf, DomainError> {
    let Some(raw) = path.to_str() else {
        return Err(DomainError::InvalidEnvironmentLayout(format!(
            "{var_name} contains non-UTF-8 characters"
        )));
    };
    if raw.is_empty() || !path.is_absolute() || path == Path::new("/") {
        return Err(DomainError::InvalidEnvironmentLayout(format!(
            "{var_name} must be a non-root absolute path"
        )));
    }
    if raw
        .chars()
        .any(|c| c == '\0' || c.is_control() || is_bidi_or_invisible_format(c))
    {
        return Err(DomainError::InvalidEnvironmentLayout(format!(
            "{var_name} contains forbidden control or BiDi characters"
        )));
    }
    if raw.contains("/./") || raw.ends_with("/.") {
        return Err(DomainError::InvalidEnvironmentLayout(format!(
            "{var_name} must not contain '.' components"
        )));
    }

    let mut normalized = PathBuf::new();
    let mut segment_count = 0usize;
    for component in path.components() {
        match component {
            Component::RootDir => normalized.push("/"),
            Component::Normal(seg) => {
                let s = seg.to_str().ok_or_else(|| {
                    DomainError::InvalidEnvironmentLayout(format!(
                        "{var_name} contains non-UTF-8 characters"
                    ))
                })?;
                if s.starts_with('-') {
                    return Err(DomainError::InvalidEnvironmentLayout(format!(
                        "{var_name} components must not start with '-'"
                    )));
                }
                normalized.push(s);
                segment_count += 1;
            }
            Component::ParentDir => {
                return Err(DomainError::InvalidEnvironmentLayout(format!(
                    "{var_name} must not contain '..' traversal components"
                )));
            }
            Component::CurDir => {
                return Err(DomainError::InvalidEnvironmentLayout(format!(
                    "{var_name} must not contain '.' components"
                )));
            }
            Component::Prefix(_) => {
                return Err(DomainError::InvalidEnvironmentLayout(format!(
                    "{var_name} must be a POSIX absolute path"
                )));
            }
        }
    }

    if segment_count == 0 {
        return Err(DomainError::InvalidEnvironmentLayout(format!(
            "{var_name} must be a non-root absolute path"
        )));
    }

    Ok(normalized)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOptions {
    pub source_path: PathBuf,
    pub move_source: bool,
    pub custom_name: Option<String>,
    pub no_cli: bool,
    pub force: bool,
    pub dry_run: bool,
    pub expected_sha256: Option<String>,
}

pub fn validate_sha256_hex(raw: &str) -> Result<String, DomainError> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DomainError::InvalidSha256(raw.to_string()));
    }
    Ok(raw.to_ascii_lowercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledApp {
    pub slug: AppSlug,
    pub name: String,
    pub version: Option<String>,
    pub appimage_path: PathBuf,
    pub stable_symlink_path: Option<PathBuf>,
    pub cli_symlink_path: Option<PathBuf>,
    pub desktop_file_path: PathBuf,
    pub icon_paths: Vec<PathBuf>,
    pub sha256: String,
    pub desktop_file_sha256: Option<String>,
    pub icon_sha256s: BTreeMap<String, String>,
    pub installed_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRefreshOutcome {
    pub tool: String,
    pub executed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSummary {
    pub dry_run: bool,
    pub updated_existing: bool,
    pub installed_app: InstalledApp,
    pub removed_obsolete_paths: Vec<PathBuf>,
    pub warnings: Vec<String>,
    pub cache_outcomes: Vec<CacheRefreshOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallOptions {
    pub target: String,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallSummary {
    pub dry_run: bool,
    pub removed_app: InstalledApp,
    pub removed_paths: Vec<PathBuf>,
    pub warnings: Vec<String>,
    pub cache_outcomes: Vec<CacheRefreshOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedApp {
    pub app: InstalledApp,
    pub binary_present: bool,
    pub desktop_present: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorCheckStatus {
    Ok,
    Warning,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub name: String,
    pub status: DoctorCheckStatus,
    pub detail: String,
    pub pacman_package: Option<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub missing_pacman_packages: Vec<String>,
    pub healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOptions {
    pub target: Option<String>,
    pub strict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyEntryStatus {
    Ok,
    Sha256Mismatch,
    Missing,
    NotRegularFile,
    UnsafePath,
    ArtifactError,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyArtifactCheck {
    pub kind: &'static str,
    pub path: PathBuf,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyEntryResult {
    pub slug: AppSlug,
    pub name: String,
    pub version: Option<String>,
    pub appimage_path: PathBuf,
    pub status: VerifyEntryStatus,
    pub expected_sha256: String,
    pub actual_sha256: Option<String>,
    pub detail: String,
    pub artifact_checks: Vec<VerifyArtifactCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: Vec<VerifyEntryResult>,
    pub all_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateRegistryOptions {
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateRegistryEntryStatus {
    Migrated,
    Unchanged,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateRegistryEntryResult {
    pub slug: AppSlug,
    pub name: String,
    pub status: MigrateRegistryEntryStatus,
    pub desktop_hash_added: bool,
    pub icons_hashed: usize,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateRegistryReport {
    pub dry_run: bool,
    pub previous_schema_version: Option<u32>,
    pub target_schema_version: u32,
    pub registry_written: bool,
    pub already_up_to_date: bool,
    pub migrated_count: usize,
    pub unchanged_count: usize,
    pub failed_count: usize,
    pub entries: Vec<MigrateRegistryEntryResult>,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{XdgLayout, validate_sha256_hex};

    #[test]
    fn validates_sha256_hex_digest_length_and_charset() {
        let upper = "A".repeat(64);
        assert_eq!(validate_sha256_hex(&upper).unwrap(), "a".repeat(64));

        assert!(validate_sha256_hex("").is_err());
        assert!(validate_sha256_hex(&"a".repeat(63)).is_err());
        assert!(validate_sha256_hex(&"a".repeat(65)).is_err());
        assert!(validate_sha256_hex(&format!("{}g", "a".repeat(63))).is_err());
        assert!(validate_sha256_hex(&format!(" {} ", "a".repeat(64))).is_err());
    }

    #[test]
    fn rejects_relative_traversal_or_control_chars_in_env_paths() {
        assert!(XdgLayout::try_from_env_values(Path::new("relative/home"), None).is_err());
        assert!(XdgLayout::try_from_env_values(Path::new("/"), None).is_err());
        assert!(XdgLayout::try_from_env_values(Path::new("/home/../etc"), None).is_err());
        assert!(XdgLayout::try_from_env_values(Path::new("/home/-evil"), None).is_err());
        assert!(XdgLayout::try_from_env_values(Path::new("/home/user\u{202E}"), None).is_err());
        assert!(
            XdgLayout::try_from_env_values(Path::new("/home/user"), Some(Path::new("relative")))
                .is_err()
        );
        assert!(
            XdgLayout::try_from_env_values(
                Path::new("/home/user"),
                Some(Path::new("/home/user/-dash"))
            )
            .is_err()
        );
        assert!(
            XdgLayout::try_from_env_values(Path::new("/home/user"), Some(Path::new("/tmp/../etc")))
                .is_err()
        );
        assert!(
            XdgLayout::try_from_env_values(
                Path::new("/home/user"),
                Some(Path::new("/home/user/.local/share"))
            )
            .is_ok()
        );
        assert!(XdgLayout::try_from_env_values(Path::new("/home/u/./extra"), None).is_err());
        assert!(
            XdgLayout::try_from_env_values(Path::new("/home/u"), Some(Path::new("/tmp/xdg/.")))
                .is_err()
        );
        assert!(XdgLayout::try_from_env_values(Path::new("///"), None).is_err());

        let normalized = XdgLayout::try_from_env_values(
            Path::new("/home/u///"),
            Some(Path::new("/home/u/.local//share/")),
        )
        .unwrap();
        assert_eq!(
            normalized.applications_dir.as_os_str(),
            "/home/u/Applications"
        );
        assert_eq!(normalized.bin_dir.as_os_str(), "/home/u/.local/bin");
        assert_eq!(
            normalized.desktop_entries_dir.as_os_str(),
            "/home/u/.local/share/applications"
        );
        assert_eq!(
            normalized.icons_hicolor_dir.as_os_str(),
            "/home/u/.local/share/icons/hicolor"
        );
        assert_eq!(
            normalized.registry_path.as_os_str(),
            "/home/u/.local/share/install-appimage/registry.json"
        );
    }
}

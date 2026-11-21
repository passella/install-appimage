use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use rustix::fs::{Mode, OFlags, open};
use serde::{Deserialize, Serialize};

use crate::adapters::outbound::xdg_fs::verify_no_symlink_dirs_under_root;
use crate::domain::error::DomainError;
use crate::domain::models::{InstalledApp, XdgLayout, validate_sha256_hex};
use crate::domain::path_safety::{
    normalize_and_validate_icon_sha256s, validate_installed_app_against_layout,
};
use crate::domain::ports::{FileSystemPort, LoadedRegistry, RegistryPort};
use crate::domain::slug::AppSlug;

const CURRENT_REGISTRY_SCHEMA_VERSION: u32 = 2;
const MIN_SUPPORTED_REGISTRY_SCHEMA_VERSION: u32 = 1;
const MAX_REGISTRY_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
struct RegistryDocumentDto {
    schema_version: u32,
    apps: Vec<InstalledAppDto>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstalledAppDto {
    id: String,
    slug: String,
    name: String,
    version: Option<String>,
    appimage_path: PathBuf,
    stable_symlink_path: Option<PathBuf>,
    cli_symlink_path: Option<PathBuf>,
    desktop_file_path: PathBuf,
    icon_paths: Vec<PathBuf>,
    sha256: String,
    #[serde(default)]
    desktop_file_sha256: Option<String>,
    #[serde(default)]
    icon_sha256s: BTreeMap<String, String>,
    installed_at: String,
}

pub struct JsonRegistryAdapter<'a> {
    fs: &'a dyn FileSystemPort,
}

impl<'a> JsonRegistryAdapter<'a> {
    pub fn new(fs: &'a dyn FileSystemPort) -> Self {
        Self { fs }
    }
}

impl RegistryPort for JsonRegistryAdapter<'_> {
    fn load(&self, layout: &XdgLayout) -> Result<Vec<InstalledApp>, DomainError> {
        Ok(self.load_with_meta(layout)?.apps)
    }

    fn load_with_meta(&self, layout: &XdgLayout) -> Result<LoadedRegistry, DomainError> {
        let registry_path = &layout.registry_path;
        let Some(reg_parent) = registry_path.parent() else {
            return Err(DomainError::UnsafeManagedPath(registry_path.clone()));
        };
        verify_no_symlink_dirs_under_root(reg_parent, reg_parent, true)?;

        let fd = match open(
            registry_path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => {
                return Ok(LoadedRegistry {
                    schema_version: None,
                    apps: Vec::new(),
                });
            }
            Err(rustix::io::Errno::LOOP) => {
                return Err(DomainError::RegistryCorrupted {
                    path: registry_path.clone(),
                    reason: "registry file must not be a symlink".to_string(),
                });
            }
            Err(errno) => {
                return Err(DomainError::Io {
                    context: format!("reading registry '{}'", registry_path.display()),
                    reason: errno.to_string(),
                });
            }
        };

        let file = File::from(fd);
        let meta = file.metadata().map_err(|err| DomainError::Io {
            context: format!("statting registry '{}'", registry_path.display()),
            reason: err.to_string(),
        })?;
        if !meta.is_file() {
            return Err(DomainError::RegistryCorrupted {
                path: registry_path.clone(),
                reason: "registry path is not a regular file".to_string(),
            });
        }
        if meta.len() > MAX_REGISTRY_BYTES {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "registry.json".to_string(),
                limit: MAX_REGISTRY_BYTES,
                context: registry_path.display().to_string(),
            });
        }

        let mut raw_bytes = Vec::with_capacity((meta.len() as usize).min(64 * 1024));
        file.take(MAX_REGISTRY_BYTES + 1)
            .read_to_end(&mut raw_bytes)
            .map_err(|err| DomainError::Io {
                context: format!("reading registry '{}'", registry_path.display()),
                reason: err.to_string(),
            })?;
        if (raw_bytes.len() as u64) > MAX_REGISTRY_BYTES {
            return Err(DomainError::ResourceLimitExceeded {
                resource: "registry.json".to_string(),
                limit: MAX_REGISTRY_BYTES,
                context: registry_path.display().to_string(),
            });
        }

        let doc: RegistryDocumentDto =
            serde_json::from_slice(&raw_bytes).map_err(|err| DomainError::RegistryCorrupted {
                path: registry_path.clone(),
                reason: err.to_string(),
            })?;

        if !(MIN_SUPPORTED_REGISTRY_SCHEMA_VERSION..=CURRENT_REGISTRY_SCHEMA_VERSION)
            .contains(&doc.schema_version)
        {
            return Err(DomainError::RegistryCorrupted {
                path: registry_path.clone(),
                reason: format!("unsupported schema_version {}", doc.schema_version),
            });
        }

        let mut seen_slugs: HashSet<AppSlug> = HashSet::with_capacity(doc.apps.len());
        let mut apps = Vec::with_capacity(doc.apps.len());
        for dto in doc.apps {
            let slug =
                AppSlug::parse_strict(&dto.slug).map_err(|_| DomainError::RegistryCorrupted {
                    path: registry_path.clone(),
                    reason: format!("invalid stored slug '{}'", dto.slug),
                })?;
            if !seen_slugs.insert(slug.clone()) {
                return Err(DomainError::RegistryCorrupted {
                    path: registry_path.clone(),
                    reason: format!("duplicate slug '{}' in registry", slug.as_str()),
                });
            }

            let desktop_file_sha256 = dto
                .desktop_file_sha256
                .as_deref()
                .map(validate_sha256_hex)
                .transpose()
                .map_err(|err| DomainError::RegistryCorrupted {
                    path: registry_path.clone(),
                    reason: err.to_string(),
                })?;

            let icon_sha256s = normalize_and_validate_icon_sha256s(
                &dto.icon_paths,
                &dto.icon_sha256s,
                &layout.icons_hicolor_dir,
                slug.as_str(),
            )
            .map_err(|err| DomainError::RegistryCorrupted {
                path: registry_path.clone(),
                reason: err.to_string(),
            })?;

            let app = InstalledApp {
                slug,
                name: dto.name,
                version: dto.version,
                appimage_path: dto.appimage_path,
                stable_symlink_path: dto.stable_symlink_path,
                cli_symlink_path: dto.cli_symlink_path,
                desktop_file_path: dto.desktop_file_path,
                icon_paths: dto.icon_paths,
                sha256: dto.sha256,
                desktop_file_sha256,
                icon_sha256s,
                installed_at: dto.installed_at,
            };
            validate_installed_app_against_layout(&app, layout).map_err(|err| {
                DomainError::RegistryCorrupted {
                    path: registry_path.clone(),
                    reason: err.to_string(),
                }
            })?;
            apps.push(app);
        }

        Ok(LoadedRegistry {
            schema_version: Some(doc.schema_version),
            apps,
        })
    }

    fn save(
        &self,
        layout: &XdgLayout,
        apps: &[InstalledApp],
        dry_run: bool,
    ) -> Result<(), DomainError> {
        if dry_run {
            return Ok(());
        }
        let registry_path = &layout.registry_path;
        let Some(parent) = registry_path.parent() else {
            return Err(DomainError::UnsafeManagedPath(registry_path.clone()));
        };
        self.fs.create_dir_all_safe(parent, parent, false)?;

        let dtos: Vec<InstalledAppDto> = apps
            .iter()
            .map(|app| InstalledAppDto {
                id: app.slug.as_str().to_string(),
                slug: app.slug.as_str().to_string(),
                name: app.name.clone(),
                version: app.version.clone(),
                appimage_path: app.appimage_path.clone(),
                stable_symlink_path: app.stable_symlink_path.clone(),
                cli_symlink_path: app.cli_symlink_path.clone(),
                desktop_file_path: app.desktop_file_path.clone(),
                icon_paths: app.icon_paths.clone(),
                sha256: app.sha256.clone(),
                desktop_file_sha256: app.desktop_file_sha256.clone(),
                icon_sha256s: app.icon_sha256s.clone(),
                installed_at: app.installed_at.clone(),
            })
            .collect();

        let doc = RegistryDocumentDto {
            schema_version: CURRENT_REGISTRY_SCHEMA_VERSION,
            apps: dtos,
        };
        let json = serde_json::to_vec_pretty(&doc).map_err(|err| DomainError::Io {
            context: format!("serializing registry '{}'", registry_path.display()),
            reason: err.to_string(),
        })?;

        self.fs
            .write_file_atomic(parent, registry_path, &json, 0o644, false)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;

    use crate::adapters::outbound::xdg_fs::XdgFileSystemAdapter;
    use crate::domain::error::DomainError;
    use crate::domain::models::{InstalledApp, XdgLayout};
    use crate::domain::ports::RegistryPort;
    use crate::domain::slug::AppSlug;

    use super::JsonRegistryAdapter;

    #[test]
    fn loads_v1_backwards_compatibly_saves_v2_and_rejects_invalid_v2_hashes_or_keys() {
        let tmp = TempDir::new().unwrap();
        let data_home = tmp.path().join(".local/share");
        let layout = XdgLayout::try_from_env_values(tmp.path(), Some(&data_home)).unwrap();
        let fs_adapter = XdgFileSystemAdapter;
        let reg = JsonRegistryAdapter::new(&fs_adapter);

        let appimage_path = layout.applications_dir.join("Demo-1.0.AppImage");
        let desktop_path = layout.desktop_entries_dir.join("demo.desktop");
        let icon_path = layout.icons_hicolor_dir.join("256x256/apps/demo.png");
        fs::create_dir_all(layout.registry_path.parent().unwrap()).unwrap();

        let v1_json = format!(
            "{{\"schema_version\":1,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":\"1.0\",\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[\"{}\"],\"sha256\":\"{}\",\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
            appimage_path.display(),
            desktop_path.display(),
            icon_path.display(),
            "a".repeat(64),
        );
        fs::write(&layout.registry_path, v1_json).unwrap();

        let loaded_v1 = reg.load(&layout).unwrap();
        assert_eq!(loaded_v1.len(), 1);
        assert_eq!(loaded_v1[0].desktop_file_sha256, None);
        assert!(loaded_v1[0].icon_sha256s.is_empty());

        let mut icon_sha256s = BTreeMap::new();
        icon_sha256s.insert(icon_path.to_string_lossy().into_owned(), "B".repeat(64));
        let v2_app = InstalledApp {
            slug: AppSlug::parse_strict("demo").unwrap(),
            name: "Demo".to_string(),
            version: Some("1.0".to_string()),
            appimage_path: appimage_path.clone(),
            stable_symlink_path: None,
            cli_symlink_path: None,
            desktop_file_path: desktop_path.clone(),
            icon_paths: vec![icon_path.clone()],
            sha256: "a".repeat(64),
            desktop_file_sha256: Some("C".repeat(64)),
            icon_sha256s,
            installed_at: "2026-11-21T10:00:00Z".to_string(),
        };
        reg.save(&layout, &[v2_app], false).unwrap();

        let saved_raw = fs::read_to_string(&layout.registry_path).unwrap();
        assert!(saved_raw.contains("\"schema_version\": 2"));
        let loaded_v2 = reg.load(&layout).unwrap();
        assert_eq!(
            loaded_v2[0].desktop_file_sha256.as_deref(),
            Some("c".repeat(64).as_str())
        );
        assert_eq!(
            loaded_v2[0]
                .icon_sha256s
                .get(icon_path.to_str().unwrap())
                .map(String::as_str),
            Some("b".repeat(64).as_str())
        );

        let bad_schema = "{\"schema_version\":3,\"apps\":[]}";
        fs::write(&layout.registry_path, bad_schema).unwrap();
        assert!(matches!(
            reg.load(&layout),
            Err(DomainError::RegistryCorrupted { .. })
        ));

        let bad_desktop_sha = format!(
            "{{\"schema_version\":2,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":null,\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[],\"sha256\":\"{}\",\"desktop_file_sha256\":\"short\",\"icon_sha256s\":{{}},\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
            appimage_path.display(),
            desktop_path.display(),
            "a".repeat(64),
        );
        fs::write(&layout.registry_path, bad_desktop_sha).unwrap();
        assert!(matches!(
            reg.load(&layout),
            Err(DomainError::RegistryCorrupted { .. })
        ));

        let bad_icon_hash = format!(
            "{{\"schema_version\":2,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":null,\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[\"{}\"],\"sha256\":\"{}\",\"desktop_file_sha256\":null,\"icon_sha256s\":{{\"{}\":\"not-hex\"}},\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
            appimage_path.display(),
            desktop_path.display(),
            icon_path.display(),
            "a".repeat(64),
            icon_path.display(),
        );
        fs::write(&layout.registry_path, bad_icon_hash).unwrap();
        assert!(matches!(
            reg.load(&layout),
            Err(DomainError::RegistryCorrupted { .. })
        ));

        let bad_icon_key = format!(
            "{{\"schema_version\":2,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":null,\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[\"{}\"],\"sha256\":\"{}\",\"desktop_file_sha256\":null,\"icon_sha256s\":{{\"/etc/passwd\":\"{}\"}},\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
            appimage_path.display(),
            desktop_path.display(),
            icon_path.display(),
            "a".repeat(64),
            "d".repeat(64),
        );
        fs::write(&layout.registry_path, bad_icon_key).unwrap();
        assert!(matches!(
            reg.load(&layout),
            Err(DomainError::RegistryCorrupted { .. })
        ));

        let unlisted_icon_key = format!(
            "{{\"schema_version\":2,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":null,\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[],\"sha256\":\"{}\",\"desktop_file_sha256\":null,\"icon_sha256s\":{{\"{}\":\"{}\"}},\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
            appimage_path.display(),
            desktop_path.display(),
            "a".repeat(64),
            icon_path.display(),
            "d".repeat(64),
        );
        fs::write(&layout.registry_path, unlisted_icon_key).unwrap();
        assert!(matches!(
            reg.load(&layout),
            Err(DomainError::RegistryCorrupted { .. })
        ));
    }

    #[test]
    fn rejects_non_canonical_paths_and_duplicate_icon_keys_in_registry() {
        let tmp = TempDir::new().unwrap();
        let data_home = tmp.path().join(".local/share");
        let layout = XdgLayout::try_from_env_values(tmp.path(), Some(&data_home)).unwrap();
        let fs_adapter = XdgFileSystemAdapter;
        let reg = JsonRegistryAdapter::new(&fs_adapter);

        let appimage_path = layout.applications_dir.join("Demo-1.0.AppImage");
        let desktop_path = layout.desktop_entries_dir.join("demo.desktop");
        let icon_path = layout.icons_hicolor_dir.join("256x256/apps/demo.png");
        fs::create_dir_all(layout.registry_path.parent().unwrap()).unwrap();

        let digest_a = "a".repeat(64);
        let digest_b = "b".repeat(64);

        let non_canonical_icon_keys = [
            format!(
                "{}/256x256/apps/./demo.png",
                layout.icons_hicolor_dir.display()
            ),
            format!(
                "{}/256x256//apps/demo.png",
                layout.icons_hicolor_dir.display()
            ),
            format!(
                "{}/256x256/apps/demo.png/",
                layout.icons_hicolor_dir.display()
            ),
        ];

        for bad_key in &non_canonical_icon_keys {
            let payload_key_only = format!(
                "{{\"schema_version\":2,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":null,\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[\"{}\"],\"sha256\":\"{}\",\"desktop_file_sha256\":null,\"icon_sha256s\":{{\"{}\":\"{}\"}},\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
                appimage_path.display(),
                desktop_path.display(),
                icon_path.display(),
                digest_a,
                bad_key,
                digest_b,
            );
            fs::write(&layout.registry_path, payload_key_only).unwrap();
            assert!(matches!(
                reg.load(&layout),
                Err(DomainError::RegistryCorrupted { .. })
            ));

            let payload_both_non_canonical = format!(
                "{{\"schema_version\":2,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":null,\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[\"{}\"],\"sha256\":\"{}\",\"desktop_file_sha256\":null,\"icon_sha256s\":{{\"{}\":\"{}\"}},\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
                appimage_path.display(),
                desktop_path.display(),
                bad_key,
                digest_a,
                bad_key,
                digest_b,
            );
            fs::write(&layout.registry_path, payload_both_non_canonical).unwrap();
            assert!(matches!(
                reg.load(&layout),
                Err(DomainError::RegistryCorrupted { .. })
            ));
        }

        let dup_normalized_keys = format!(
            "{{\"schema_version\":2,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":null,\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[\"{}\"],\"sha256\":\"{}\",\"desktop_file_sha256\":null,\"icon_sha256s\":{{\"{}\":\"{}\",\"{}\":\"{}\"}},\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
            appimage_path.display(),
            desktop_path.display(),
            icon_path.display(),
            digest_a,
            icon_path.display(),
            digest_b,
            non_canonical_icon_keys[0],
            digest_a,
        );
        fs::write(&layout.registry_path, dup_normalized_keys).unwrap();
        assert!(matches!(
            reg.load(&layout),
            Err(DomainError::RegistryCorrupted { .. })
        ));

        let bad_desktop = format!("{}/./demo.desktop", layout.desktop_entries_dir.display());
        let bad_appimage = format!("{}/Demo-1.0.AppImage/", layout.applications_dir.display());
        let bad_stable = format!("{}/./demo.AppImage", layout.applications_dir.display());
        let bad_cli = format!("{}/demo/", layout.bin_dir.display());

        for (app_p, stable_p, cli_p, desk_p) in [
            (
                bad_appimage.as_str(),
                "null".to_string(),
                "null".to_string(),
                desktop_path.display().to_string(),
            ),
            (
                appimage_path.display().to_string().as_str(),
                format!("\"{bad_stable}\""),
                "null".to_string(),
                desktop_path.display().to_string(),
            ),
            (
                appimage_path.display().to_string().as_str(),
                "null".to_string(),
                format!("\"{bad_cli}\""),
                desktop_path.display().to_string(),
            ),
            (
                appimage_path.display().to_string().as_str(),
                "null".to_string(),
                "null".to_string(),
                bad_desktop,
            ),
        ] {
            let payload = format!(
                "{{\"schema_version\":2,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":null,\"appimage_path\":\"{app_p}\",\"stable_symlink_path\":{stable_p},\"cli_symlink_path\":{cli_p},\"desktop_file_path\":\"{desk_p}\",\"icon_paths\":[],\"sha256\":\"{digest_a}\",\"desktop_file_sha256\":null,\"icon_sha256s\":{{}},\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}"
            );
            fs::write(&layout.registry_path, payload).unwrap();
            assert!(matches!(
                reg.load(&layout),
                Err(DomainError::RegistryCorrupted { .. })
            ));
        }
    }
}

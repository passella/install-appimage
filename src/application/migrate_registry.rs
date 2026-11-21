use std::path::Path;

use crate::domain::error::DomainError;
use crate::domain::models::{
    InstalledApp, MigrateRegistryEntryResult, MigrateRegistryEntryStatus, MigrateRegistryOptions,
    MigrateRegistryReport, XdgLayout,
};
use crate::domain::path_safety::validate_installed_app_against_layout;
use crate::domain::ports::{FileSystemPort, ManagedFileHashProbe, RegistryPort};

const TARGET_REGISTRY_SCHEMA_VERSION: u32 = 2;

pub struct MigrateRegistryUseCase<'a> {
    fs: &'a dyn FileSystemPort,
    registry: &'a dyn RegistryPort,
}

impl<'a> MigrateRegistryUseCase<'a> {
    pub fn new(fs: &'a dyn FileSystemPort, registry: &'a dyn RegistryPort) -> Self {
        Self { fs, registry }
    }

    pub fn execute(
        &self,
        layout: &XdgLayout,
        options: &MigrateRegistryOptions,
    ) -> Result<MigrateRegistryReport, DomainError> {
        let mut loaded = self.registry.load_with_meta(layout)?;
        loaded.apps.sort_by(|a, b| a.slug.cmp(&b.slug));

        let mut updated_apps = Vec::with_capacity(loaded.apps.len());
        let mut entries = Vec::with_capacity(loaded.apps.len());
        let mut migrated_count = 0usize;
        let mut unchanged_count = 0usize;
        let mut failed_count = 0usize;

        for app in loaded.apps {
            let (entry, next_app) = self.migrate_single_app(layout, app);
            match entry.status {
                MigrateRegistryEntryStatus::Migrated => migrated_count += 1,
                MigrateRegistryEntryStatus::Unchanged => unchanged_count += 1,
                MigrateRegistryEntryStatus::Error => failed_count += 1,
            }
            entries.push(entry);
            updated_apps.push(next_app);
        }

        let schema_needs_upgrade = loaded.schema_version == Some(1);
        let needs_write = migrated_count > 0 || schema_needs_upgrade;
        let mut registry_written = false;

        if failed_count == 0 && needs_write && !options.dry_run {
            self.registry.save(layout, &updated_apps, false)?;
            registry_written = true;
        }

        let already_up_to_date = failed_count == 0 && !needs_write;

        Ok(MigrateRegistryReport {
            dry_run: options.dry_run,
            previous_schema_version: loaded.schema_version,
            target_schema_version: TARGET_REGISTRY_SCHEMA_VERSION,
            registry_written,
            already_up_to_date,
            migrated_count,
            unchanged_count,
            failed_count,
            entries,
        })
    }

    fn migrate_single_app(
        &self,
        layout: &XdgLayout,
        app: InstalledApp,
    ) -> (MigrateRegistryEntryResult, InstalledApp) {
        if let Err(err) = validate_installed_app_against_layout(&app, layout) {
            return (
                MigrateRegistryEntryResult {
                    slug: app.slug.clone(),
                    name: app.name.clone(),
                    status: MigrateRegistryEntryStatus::Error,
                    desktop_hash_added: false,
                    icons_hashed: 0,
                    detail: err.to_string(),
                },
                app,
            );
        }

        let mut candidate = app.clone();
        let mut errors: Vec<String> = Vec::new();
        let mut desktop_hash_added = false;
        let mut icons_hashed = 0usize;

        if candidate.desktop_file_sha256.is_none() {
            match self.hash_required_artifact(
                "desktop",
                &layout.desktop_entries_dir,
                &candidate.desktop_file_path,
            ) {
                Ok(digest) => {
                    candidate.desktop_file_sha256 = Some(digest);
                    desktop_hash_added = true;
                }
                Err(err) => errors.push(err),
            }
        }

        for icon_path in &candidate.icon_paths {
            let Some(key) = icon_path.to_str() else {
                errors.push(format!("icon '{}': non-UTF-8 path", icon_path.display()));
                continue;
            };
            if !candidate.icon_sha256s.contains_key(key) {
                match self.hash_required_artifact("icon", &layout.icons_hicolor_dir, icon_path) {
                    Ok(digest) => {
                        candidate.icon_sha256s.insert(key.to_string(), digest);
                        icons_hashed += 1;
                    }
                    Err(err) => errors.push(err),
                }
            }
        }

        if !errors.is_empty() {
            return (
                MigrateRegistryEntryResult {
                    slug: app.slug.clone(),
                    name: app.name.clone(),
                    status: MigrateRegistryEntryStatus::Error,
                    desktop_hash_added: false,
                    icons_hashed: 0,
                    detail: errors.join("; "),
                },
                app,
            );
        }

        if desktop_hash_added || icons_hashed > 0 {
            let detail = format!(
                "computed hashes (desktop: {}, icons: {icons_hashed})",
                if desktop_hash_added { "added" } else { "kept" }
            );
            (
                MigrateRegistryEntryResult {
                    slug: candidate.slug.clone(),
                    name: candidate.name.clone(),
                    status: MigrateRegistryEntryStatus::Migrated,
                    desktop_hash_added,
                    icons_hashed,
                    detail,
                },
                candidate,
            )
        } else {
            (
                MigrateRegistryEntryResult {
                    slug: candidate.slug.clone(),
                    name: candidate.name.clone(),
                    status: MigrateRegistryEntryStatus::Unchanged,
                    desktop_hash_added: false,
                    icons_hashed: 0,
                    detail: "all v2 artifact hashes already recorded".to_string(),
                },
                candidate,
            )
        }
    }

    fn hash_required_artifact(
        &self,
        kind: &str,
        root: &Path,
        path: &Path,
    ) -> Result<String, String> {
        match self.fs.hash_managed_regular_file(root, path) {
            Ok(ManagedFileHashProbe::Hashed(hex)) => Ok(hex),
            Ok(ManagedFileHashProbe::Missing) => {
                Err(format!("{kind} '{}': file is missing", path.display()))
            }
            Ok(ManagedFileHashProbe::NotRegularFile(reason)) => {
                Err(format!("{kind} '{}': {reason}", path.display()))
            }
            Ok(ManagedFileHashProbe::UnsafePath(reason)) => {
                Err(format!("{kind} '{}': {reason}", path.display()))
            }
            Err(err) => Err(format!("{kind} '{}': {err}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::symlink;

    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use crate::adapters::outbound::json_registry::JsonRegistryAdapter;
    use crate::adapters::outbound::xdg_fs::XdgFileSystemAdapter;
    use crate::domain::models::{MigrateRegistryEntryStatus, MigrateRegistryOptions, XdgLayout};
    use crate::domain::ports::RegistryPort;

    use super::MigrateRegistryUseCase;

    #[test]
    fn migrates_v1_registry_is_idempotent_and_fails_closed_on_missing_or_symlink_artifacts() {
        let tmp = TempDir::new().unwrap();
        let data_home = tmp.path().join(".local/share");
        let layout = XdgLayout::try_from_env_values(tmp.path(), Some(&data_home)).unwrap();
        let fs_adapter = XdgFileSystemAdapter;
        let registry = JsonRegistryAdapter::new(&fs_adapter);
        let migrate_uc = MigrateRegistryUseCase::new(&fs_adapter, &registry);

        let no_reg = migrate_uc
            .execute(&layout, &MigrateRegistryOptions { dry_run: false })
            .unwrap();
        assert!(no_reg.already_up_to_date);
        assert!(!no_reg.registry_written);
        assert_eq!(no_reg.previous_schema_version, None);
        assert!(!layout.registry_path.exists());

        let appimage_path = layout.applications_dir.join("Demo-1.0.AppImage");
        let desktop_path = layout.desktop_entries_dir.join("demo.desktop");
        let icon_png = layout.icons_hicolor_dir.join("256x256/apps/demo.png");
        let icon_svg = layout.icons_hicolor_dir.join("scalable/apps/demo.svg");
        fs::create_dir_all(&layout.applications_dir).unwrap();
        fs::create_dir_all(&layout.desktop_entries_dir).unwrap();
        fs::create_dir_all(icon_png.parent().unwrap()).unwrap();
        fs::create_dir_all(icon_svg.parent().unwrap()).unwrap();
        fs::create_dir_all(layout.registry_path.parent().unwrap()).unwrap();

        let desktop_bytes = b"[Desktop Entry]\nType=Application\nName=Demo\n";
        let png_bytes = b"PNG-ICON";
        let svg_bytes = b"<svg></svg>";
        fs::write(&appimage_path, b"APPIMAGE").unwrap();
        fs::write(&desktop_path, desktop_bytes).unwrap();
        fs::write(&icon_png, png_bytes).unwrap();
        fs::write(&icon_svg, svg_bytes).unwrap();

        let v1_json = format!(
            "{{\"schema_version\":1,\"apps\":[{{\"id\":\"demo\",\"slug\":\"demo\",\"name\":\"Demo\",\"version\":\"1.0\",\"appimage_path\":\"{}\",\"stable_symlink_path\":null,\"cli_symlink_path\":null,\"desktop_file_path\":\"{}\",\"icon_paths\":[\"{}\",\"{}\"],\"sha256\":\"{}\",\"installed_at\":\"2026-11-21T10:00:00Z\"}}]}}",
            appimage_path.display(),
            desktop_path.display(),
            icon_png.display(),
            icon_svg.display(),
            "a".repeat(64),
        );
        fs::write(&layout.registry_path, &v1_json).unwrap();

        let dry = migrate_uc
            .execute(&layout, &MigrateRegistryOptions { dry_run: true })
            .unwrap();
        assert!(dry.dry_run);
        assert!(!dry.registry_written);
        assert!(!dry.already_up_to_date);
        assert_eq!(dry.previous_schema_version, Some(1));
        assert_eq!(dry.migrated_count, 1);
        assert_eq!(dry.failed_count, 0);
        assert_eq!(dry.entries[0].status, MigrateRegistryEntryStatus::Migrated);
        assert!(dry.entries[0].desktop_hash_added);
        assert_eq!(dry.entries[0].icons_hashed, 2);
        assert_eq!(
            registry.load_with_meta(&layout).unwrap().schema_version,
            Some(1)
        );

        let real = migrate_uc
            .execute(&layout, &MigrateRegistryOptions { dry_run: false })
            .unwrap();
        assert!(!real.dry_run);
        assert!(real.registry_written);
        assert!(!real.already_up_to_date);
        assert_eq!(real.migrated_count, 1);
        assert_eq!(real.failed_count, 0);

        let loaded = registry.load_with_meta(&layout).unwrap();
        assert_eq!(loaded.schema_version, Some(2));
        assert_eq!(
            loaded.apps[0].desktop_file_sha256.as_deref(),
            Some(hex::encode(Sha256::digest(desktop_bytes)).as_str())
        );
        let mut expected_icons = BTreeMap::new();
        expected_icons.insert(
            icon_png.to_string_lossy().into_owned(),
            hex::encode(Sha256::digest(png_bytes)),
        );
        expected_icons.insert(
            icon_svg.to_string_lossy().into_owned(),
            hex::encode(Sha256::digest(svg_bytes)),
        );
        assert_eq!(loaded.apps[0].icon_sha256s, expected_icons);

        let second = migrate_uc
            .execute(&layout, &MigrateRegistryOptions { dry_run: false })
            .unwrap();
        assert!(second.already_up_to_date);
        assert!(!second.registry_written);
        assert_eq!(second.previous_schema_version, Some(2));
        assert_eq!(second.unchanged_count, 1);
        assert_eq!(second.migrated_count, 0);
        assert_eq!(
            second.entries[0].status,
            MigrateRegistryEntryStatus::Unchanged
        );

        fs::write(&layout.registry_path, &v1_json).unwrap();
        fs::remove_file(&desktop_path).unwrap();
        symlink("/etc/passwd", &desktop_path).unwrap();
        let sym_fail = migrate_uc
            .execute(&layout, &MigrateRegistryOptions { dry_run: false })
            .unwrap();
        assert!(!sym_fail.registry_written);
        assert_eq!(sym_fail.failed_count, 1);
        assert_eq!(
            sym_fail.entries[0].status,
            MigrateRegistryEntryStatus::Error
        );
        assert!(sym_fail.entries[0].detail.contains("symbolic link"));
        assert_eq!(
            registry.load_with_meta(&layout).unwrap().schema_version,
            Some(1)
        );

        let empty_v1 = "{\"schema_version\":1,\"apps\":[]}";
        fs::write(&layout.registry_path, empty_v1).unwrap();
        let empty_migrated = migrate_uc
            .execute(&layout, &MigrateRegistryOptions { dry_run: false })
            .unwrap();
        assert!(empty_migrated.registry_written);
        assert!(!empty_migrated.already_up_to_date);
        assert_eq!(empty_migrated.previous_schema_version, Some(1));
        assert_eq!(
            registry.load_with_meta(&layout).unwrap().schema_version,
            Some(2)
        );
    }
}

use std::path::{Path, PathBuf};

use crate::application::resolve_installed_app_target;
use crate::domain::error::DomainError;
use crate::domain::models::{
    InstalledApp, VerifyArtifactCheck, VerifyEntryResult, VerifyEntryStatus, VerifyOptions,
    VerifyReport, XdgLayout, validate_sha256_hex,
};
use crate::domain::path_safety::validate_installed_app_against_layout;
use crate::domain::ports::{
    FileSystemPort, ManagedArtifactProbe, ManagedFileHashProbe, RegistryPort,
};

pub struct VerifyUseCase<'a> {
    fs: &'a dyn FileSystemPort,
    registry: &'a dyn RegistryPort,
}

impl<'a> VerifyUseCase<'a> {
    pub fn new(fs: &'a dyn FileSystemPort, registry: &'a dyn RegistryPort) -> Self {
        Self { fs, registry }
    }

    pub fn execute(
        &self,
        layout: &XdgLayout,
        options: &VerifyOptions,
    ) -> Result<VerifyReport, DomainError> {
        let mut apps = self.registry.load(layout)?;
        apps.sort_by(|a, b| a.slug.cmp(&b.slug));

        let selected: Vec<InstalledApp> = match options.target.as_deref() {
            Some(raw_target) => {
                let trimmed = raw_target.trim();
                if trimmed.is_empty() {
                    return Err(DomainError::AppNotInstalled(raw_target.to_string()));
                }
                vec![resolve_installed_app_target(&apps, trimmed)?]
            }
            None => apps,
        };

        let mut entries = Vec::with_capacity(selected.len());
        for app in selected {
            entries.push(self.verify_single_app(layout, app, options.strict));
        }

        let all_ok = entries
            .iter()
            .all(|entry| entry.status == VerifyEntryStatus::Ok);

        Ok(VerifyReport { entries, all_ok })
    }

    fn verify_single_app(
        &self,
        layout: &XdgLayout,
        app: InstalledApp,
        strict: bool,
    ) -> VerifyEntryResult {
        if let Err(err) = validate_installed_app_against_layout(&app, layout) {
            return VerifyEntryResult {
                slug: app.slug,
                name: app.name,
                version: app.version,
                appimage_path: app.appimage_path,
                status: VerifyEntryStatus::UnsafePath,
                expected_sha256: app.sha256,
                actual_sha256: None,
                detail: err.to_string(),
                artifact_checks: Vec::new(),
            };
        }

        let expected_sha256 = match validate_sha256_hex(&app.sha256) {
            Ok(hex) => hex,
            Err(err) => {
                return VerifyEntryResult {
                    slug: app.slug,
                    name: app.name,
                    version: app.version,
                    appimage_path: app.appimage_path,
                    status: VerifyEntryStatus::Error,
                    expected_sha256: app.sha256,
                    actual_sha256: None,
                    detail: err.to_string(),
                    artifact_checks: Vec::new(),
                };
            }
        };

        let (mut status, actual_sha256, mut detail) = match self
            .fs
            .hash_managed_regular_file(&layout.applications_dir, &app.appimage_path)
        {
            Ok(ManagedFileHashProbe::Hashed(actual)) => {
                if actual == expected_sha256 {
                    (
                        VerifyEntryStatus::Ok,
                        Some(actual),
                        "sha256 verified".to_string(),
                    )
                } else {
                    (
                        VerifyEntryStatus::Sha256Mismatch,
                        Some(actual),
                        "sha256 checksum mismatch".to_string(),
                    )
                }
            }
            Ok(ManagedFileHashProbe::Missing) => (
                VerifyEntryStatus::Missing,
                None,
                "AppImage file is missing on disk".to_string(),
            ),
            Ok(ManagedFileHashProbe::NotRegularFile(reason)) => {
                (VerifyEntryStatus::NotRegularFile, None, reason)
            }
            Ok(ManagedFileHashProbe::UnsafePath(reason)) => {
                (VerifyEntryStatus::UnsafePath, None, reason)
            }
            Err(err) => (VerifyEntryStatus::Error, None, err.to_string()),
        };

        let artifact_checks = if strict {
            let checks = self.verify_strict_artifacts(layout, &app);
            let failed_artifacts = checks.iter().filter(|c| !c.ok).count();
            if failed_artifacts > 0 && status == VerifyEntryStatus::Ok {
                status = VerifyEntryStatus::ArtifactError;
                detail = format!(
                    "sha256 verified, but {failed_artifacts} auxiliary artifact check(s) failed"
                );
            }
            checks
        } else {
            Vec::new()
        };

        VerifyEntryResult {
            slug: app.slug,
            name: app.name,
            version: app.version,
            appimage_path: app.appimage_path,
            status,
            expected_sha256,
            actual_sha256,
            detail,
            artifact_checks,
        }
    }

    fn verify_strict_artifacts(
        &self,
        layout: &XdgLayout,
        app: &InstalledApp,
    ) -> Vec<VerifyArtifactCheck> {
        let mut checks = Vec::with_capacity(3 + app.icon_paths.len());

        let desktop_expected = match app.desktop_file_sha256.as_deref() {
            Some(raw) => match validate_sha256_hex(raw) {
                Ok(hex) => Ok(Some(hex)),
                Err(err) => Err(err.to_string()),
            },
            None => Ok(None),
        };
        checks.push(self.check_regular_artifact(
            "desktop",
            &layout.desktop_entries_dir,
            &app.desktop_file_path,
            desktop_expected,
        ));

        if let Some(ref stable_link) = app.stable_symlink_path {
            checks.push(self.check_symlink_artifact(
                "stable_symlink",
                &layout.applications_dir,
                stable_link,
                &[app.appimage_path.as_path()],
            ));
        }

        if let Some(ref cli_link) = app.cli_symlink_path {
            let mut allowed: Vec<&Path> = Vec::with_capacity(2);
            if let Some(ref stable_link) = app.stable_symlink_path {
                allowed.push(stable_link.as_path());
            }
            allowed.push(app.appimage_path.as_path());
            checks.push(self.check_symlink_artifact(
                "cli_symlink",
                &layout.bin_dir,
                cli_link,
                &allowed,
            ));
        }

        for icon_path in &app.icon_paths {
            let icon_expected = match icon_path.to_str() {
                None => Err("icon path contains invalid UTF-8".to_string()),
                Some(key) => match app.icon_sha256s.get(key) {
                    Some(raw) => match validate_sha256_hex(raw) {
                        Ok(hex) => Ok(Some(hex)),
                        Err(err) => Err(err.to_string()),
                    },
                    None => {
                        if app
                            .icon_sha256s
                            .keys()
                            .any(|candidate| Path::new(candidate) == icon_path.as_path())
                        {
                            Err("icon_sha256s contains non-canonical key for icon path".to_string())
                        } else {
                            Ok(None)
                        }
                    }
                },
            };
            checks.push(self.check_regular_artifact(
                "icon",
                &layout.icons_hicolor_dir,
                icon_path,
                icon_expected,
            ));
        }

        for extra_key in app.icon_sha256s.keys() {
            if !app
                .icon_paths
                .iter()
                .any(|p| p.to_str() == Some(extra_key.as_str()))
            {
                checks.push(VerifyArtifactCheck {
                    kind: "icon",
                    path: PathBuf::from(extra_key),
                    ok: false,
                    detail: "icon_sha256s contains unlisted or non-canonical icon path".to_string(),
                });
            }
        }

        checks
    }

    fn check_regular_artifact(
        &self,
        kind: &'static str,
        root: &Path,
        path: &Path,
        expected_sha256: Result<Option<String>, String>,
    ) -> VerifyArtifactCheck {
        let (ok, detail) = match expected_sha256 {
            Err(err) => (false, err),
            Ok(expected) => {
                match self
                    .fs
                    .verify_managed_regular_file(root, path, expected.as_deref())
                {
                    Ok(ManagedArtifactProbe::Ok) => {
                        if expected.is_some() {
                            (true, "regular file and sha256 verified".to_string())
                        } else {
                            (true, "regular file verified".to_string())
                        }
                    }
                    Ok(ManagedArtifactProbe::Missing) => {
                        (false, "artifact file is missing".to_string())
                    }
                    Ok(ManagedArtifactProbe::Invalid(reason)) => (false, reason),
                    Ok(ManagedArtifactProbe::UnsafePath(reason)) => (false, reason),
                    Err(err) => (false, err.to_string()),
                }
            }
        };
        VerifyArtifactCheck {
            kind,
            path: path.to_path_buf(),
            ok,
            detail,
        }
    }

    fn check_symlink_artifact(
        &self,
        kind: &'static str,
        root: &Path,
        link_path: &Path,
        allowed_targets: &[&Path],
    ) -> VerifyArtifactCheck {
        let (ok, detail) = match self
            .fs
            .verify_managed_symlink(root, link_path, allowed_targets)
        {
            Ok(ManagedArtifactProbe::Ok) => (true, "symlink verified".to_string()),
            Ok(ManagedArtifactProbe::Missing) => (false, "symlink is missing".to_string()),
            Ok(ManagedArtifactProbe::Invalid(reason)) => (false, reason),
            Ok(ManagedArtifactProbe::UnsafePath(reason)) => (false, reason),
            Err(err) => (false, err.to_string()),
        };
        VerifyArtifactCheck {
            kind,
            path: link_path.to_path_buf(),
            ok,
            detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    use tempfile::TempDir;

    use crate::adapters::outbound::json_registry::JsonRegistryAdapter;
    use crate::adapters::outbound::xdg_fs::XdgFileSystemAdapter;
    use crate::domain::models::{InstalledApp, XdgLayout};
    use crate::domain::slug::AppSlug;

    use super::VerifyUseCase;

    #[test]
    fn verify_strict_artifacts_fails_closed_on_inconsistent_icon_sha256s_and_non_utf8() {
        let tmp = TempDir::new().unwrap();
        let data_home = tmp.path().join(".local/share");
        let layout = XdgLayout::try_from_env_values(tmp.path(), Some(&data_home)).unwrap();
        let fs_adapter = XdgFileSystemAdapter;
        let reg_adapter = JsonRegistryAdapter::new(&fs_adapter);
        let verify_uc = VerifyUseCase::new(&fs_adapter, &reg_adapter);

        let appimage_path = layout.applications_dir.join("Demo-1.0.AppImage");
        let desktop_path = layout.desktop_entries_dir.join("demo.desktop");
        let icon_path = layout.icons_hicolor_dir.join("256x256/apps/demo.png");
        fs::create_dir_all(&layout.applications_dir).unwrap();
        fs::create_dir_all(&layout.desktop_entries_dir).unwrap();
        fs::create_dir_all(icon_path.parent().unwrap()).unwrap();
        fs::write(&appimage_path, b"BIN").unwrap();
        fs::write(&desktop_path, b"[Desktop Entry]\n").unwrap();
        fs::write(&icon_path, b"PNG").unwrap();

        let mut icon_sha256s = BTreeMap::new();
        icon_sha256s.insert(
            format!(
                "{}/256x256/apps/./demo.png",
                layout.icons_hicolor_dir.display()
            ),
            "a".repeat(64),
        );
        icon_sha256s.insert(
            format!(
                "{}/128x128/apps/demo.png",
                layout.icons_hicolor_dir.display()
            ),
            "b".repeat(64),
        );

        let non_utf8_icon = layout
            .icons_hicolor_dir
            .join(OsStr::from_bytes(b"64x64/apps/demo-\xff.png"));

        let crafted = InstalledApp {
            slug: AppSlug::parse_strict("demo").unwrap(),
            name: "Demo".to_string(),
            version: Some("1.0".to_string()),
            appimage_path,
            stable_symlink_path: None,
            cli_symlink_path: None,
            desktop_file_path: desktop_path,
            icon_paths: vec![icon_path.clone(), non_utf8_icon],
            sha256: "a".repeat(64),
            desktop_file_sha256: None,
            icon_sha256s,
            installed_at: "2026-11-21T10:00:00Z".to_string(),
        };

        let checks = verify_uc.verify_strict_artifacts(&layout, &crafted);
        assert!(
            checks
                .iter()
                .any(|c| c.kind == "icon" && c.path == icon_path && !c.ok)
        );
        assert!(
            checks
                .iter()
                .any(|c| c.kind == "icon" && !c.ok && c.detail.contains("invalid UTF-8"))
        );
        assert!(
            checks.iter().any(|c| c.kind == "icon"
                && !c.ok
                && c.detail.contains("unlisted or non-canonical"))
        );
    }
}

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use install_appimage::application::doctor::DoctorUseCase;
use install_appimage::application::install::InstallUseCase;
use install_appimage::application::list::ListUseCase;
use install_appimage::application::migrate_registry::MigrateRegistryUseCase;
use install_appimage::application::uninstall::UninstallUseCase;
use install_appimage::application::verify::VerifyUseCase;
use install_appimage::domain::error::DomainError;
use install_appimage::domain::models::{
    CacheRefreshOutcome, DesktopFieldCode, DoctorCheck, DoctorCheckStatus, DoctorReport,
    ExtractedIcon, ExtractedMetadata, IconFormat, InspectedAppImage, InstallOptions, InstalledApp,
    MigrateRegistryEntryStatus, MigrateRegistryOptions, UninstallOptions, VerifyEntryStatus,
    VerifyOptions, XdgLayout,
};
use install_appimage::domain::ports::{
    AppImageExtractorPort, ClockPort, DesktopCachePort, FileSystemPort, LoadedRegistry,
    ManagedArtifactProbe, ManagedFileHashProbe, RegistryPort, SystemProbePort,
};
use install_appimage::domain::slug::AppSlug;
use sha2::{Digest, Sha256};

struct StubClock(&'static str);

impl ClockPort for StubClock {
    fn utc_timestamp_iso8601(&self) -> String {
        self.0.to_string()
    }
}

struct MockExtractor {
    result: Result<InspectedAppImage, DomainError>,
}

impl AppImageExtractorPort for MockExtractor {
    fn inspect_and_extract(
        &self,
        _appimage_path: &Path,
        _expected_sha256: Option<&str>,
    ) -> Result<InspectedAppImage, DomainError> {
        self.result.clone()
    }
}

struct FakeFs {
    files: RefCell<HashMap<PathBuf, Vec<u8>>>,
    symlinks: RefCell<HashMap<PathBuf, PathBuf>>,
    dirs: RefCell<HashSet<PathBuf>>,
    symlink_dirs: RefCell<HashSet<PathBuf>>,
    same_file_pairs: HashSet<(PathBuf, PathBuf)>,
    fail_install_exec: bool,
}

impl FakeFs {
    fn new() -> Self {
        Self {
            files: RefCell::new(HashMap::new()),
            symlinks: RefCell::new(HashMap::new()),
            dirs: RefCell::new(HashSet::new()),
            symlink_dirs: RefCell::new(HashSet::new()),
            same_file_pairs: HashSet::new(),
            fail_install_exec: false,
        }
    }

    fn insert_file(&self, path: &Path, content: &[u8]) {
        self.files
            .borrow_mut()
            .insert(path.to_path_buf(), content.to_vec());
    }
}

impl FileSystemPort for FakeFs {
    fn path_or_symlink_exists(&self, path: &Path) -> bool {
        self.files.borrow().contains_key(path)
            || self.symlinks.borrow().contains_key(path)
            || self.dirs.borrow().contains(path)
            || self.symlink_dirs.borrow().contains(path)
    }

    fn is_regular_non_symlink_file(&self, path: &Path) -> bool {
        self.files.borrow().contains_key(path) && !self.symlinks.borrow().contains_key(path)
    }

    fn hash_managed_regular_file(
        &self,
        root: &Path,
        path: &Path,
    ) -> Result<ManagedFileHashProbe, DomainError> {
        if self.ensure_symlink_free_path(root, path).is_err()
            || !path.starts_with(root)
            || path == root
        {
            return Ok(ManagedFileHashProbe::UnsafePath(
                "unsafe path or symlink directory".to_string(),
            ));
        }
        if self.symlinks.borrow().contains_key(path) || self.dirs.borrow().contains(path) {
            return Ok(ManagedFileHashProbe::NotRegularFile(
                "not a regular file".to_string(),
            ));
        }
        let Some(bytes) = self.files.borrow().get(path).cloned() else {
            return Ok(ManagedFileHashProbe::Missing);
        };
        Ok(ManagedFileHashProbe::Hashed(hex::encode(Sha256::digest(
            &bytes,
        ))))
    }

    fn verify_managed_regular_file(
        &self,
        root: &Path,
        path: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<ManagedArtifactProbe, DomainError> {
        if self.ensure_symlink_free_path(root, path).is_err()
            || !path.starts_with(root)
            || path == root
        {
            return Ok(ManagedArtifactProbe::UnsafePath(
                "unsafe artifact path".to_string(),
            ));
        }
        if self.symlinks.borrow().contains_key(path) || self.dirs.borrow().contains(path) {
            return Ok(ManagedArtifactProbe::Invalid(
                "not a regular file".to_string(),
            ));
        }
        let Some(bytes) = self.files.borrow().get(path).cloned() else {
            return Ok(ManagedArtifactProbe::Missing);
        };
        if let Some(expected) = expected_sha256 {
            let actual = hex::encode(Sha256::digest(&bytes));
            if actual != expected {
                return Ok(ManagedArtifactProbe::Invalid(format!(
                    "sha256 checksum mismatch (expected {expected}, got {actual})"
                )));
            }
        }
        Ok(ManagedArtifactProbe::Ok)
    }

    fn verify_managed_symlink(
        &self,
        root: &Path,
        link_path: &Path,
        allowed_targets: &[&Path],
    ) -> Result<ManagedArtifactProbe, DomainError> {
        if self.ensure_symlink_free_path(root, link_path).is_err()
            || !link_path.starts_with(root)
            || link_path == root
        {
            return Ok(ManagedArtifactProbe::UnsafePath(
                "unsafe symlink path".to_string(),
            ));
        }
        if self.files.borrow().contains_key(link_path) || self.dirs.borrow().contains(link_path) {
            return Ok(ManagedArtifactProbe::Invalid(
                "expected symbolic link, found non-symlink".to_string(),
            ));
        }
        let Some(raw_target) = self.symlinks.borrow().get(link_path).cloned() else {
            return Ok(ManagedArtifactProbe::Missing);
        };
        let resolved = if raw_target.is_absolute() {
            raw_target.clone()
        } else {
            let Some(parent) = link_path.parent() else {
                return Ok(ManagedArtifactProbe::Invalid("no parent".to_string()));
            };
            parent.join(&raw_target)
        };
        if !allowed_targets.contains(&resolved.as_path()) {
            return Ok(ManagedArtifactProbe::Invalid(format!(
                "symlink points to unexpected target '{}'",
                raw_target.display()
            )));
        }
        if self.files.borrow().contains_key(&resolved)
            || self.symlinks.borrow().contains_key(&resolved)
        {
            Ok(ManagedArtifactProbe::Ok)
        } else {
            Ok(ManagedArtifactProbe::Invalid(
                "symlink target is missing (dangling symlink)".to_string(),
            ))
        }
    }

    fn same_file(&self, left: &Path, right: &Path) -> Result<bool, DomainError> {
        Ok(left == right
            || self
                .same_file_pairs
                .contains(&(left.to_path_buf(), right.to_path_buf())))
    }

    fn ensure_symlink_free_path(&self, root: &Path, target: &Path) -> Result<(), DomainError> {
        let syms = self.symlink_dirs.borrow();
        if syms.contains(root) {
            return Err(DomainError::UnsafeManagedPath(root.to_path_buf()));
        }
        let mut cursor = target.parent();
        while let Some(dir) = cursor {
            if syms.contains(dir) {
                return Err(DomainError::UnsafeManagedPath(dir.to_path_buf()));
            }
            if dir == root {
                break;
            }
            cursor = dir.parent();
        }
        Ok(())
    }

    fn create_dir_all_safe(
        &self,
        root: &Path,
        path: &Path,
        dry_run: bool,
    ) -> Result<(), DomainError> {
        self.ensure_symlink_free_path(root, path)?;
        if self.symlink_dirs.borrow().contains(path) {
            return Err(DomainError::UnsafeManagedPath(path.to_path_buf()));
        }
        if !dry_run {
            self.dirs.borrow_mut().insert(path.to_path_buf());
        }
        Ok(())
    }

    fn install_executable_verified(
        &self,
        src: &Path,
        dst: &Path,
        _expected_sha256: &str,
        move_source: bool,
        dry_run: bool,
    ) -> Result<(), DomainError> {
        if self.fail_install_exec {
            return Err(DomainError::Io {
                context: "copying".to_string(),
                reason: "disk full".to_string(),
            });
        }
        if dry_run {
            return Ok(());
        }
        let data = self
            .files
            .borrow()
            .get(src)
            .cloned()
            .unwrap_or_else(|| b"ELF".to_vec());
        self.symlinks.borrow_mut().remove(dst);
        self.files.borrow_mut().insert(dst.to_path_buf(), data);
        if move_source && src != dst {
            self.files.borrow_mut().remove(src);
        }
        Ok(())
    }

    fn write_file_atomic(
        &self,
        root: &Path,
        path: &Path,
        contents: &[u8],
        _mode: u32,
        dry_run: bool,
    ) -> Result<(), DomainError> {
        self.ensure_symlink_free_path(root, path)?;
        if !dry_run {
            self.files
                .borrow_mut()
                .insert(path.to_path_buf(), contents.to_vec());
        }
        Ok(())
    }

    fn create_symlink_atomic(
        &self,
        root: &Path,
        target: &Path,
        link_path: &Path,
        dry_run: bool,
    ) -> Result<(), DomainError> {
        self.ensure_symlink_free_path(root, link_path)?;
        if !dry_run {
            self.symlinks
                .borrow_mut()
                .insert(link_path.to_path_buf(), target.to_path_buf());
        }
        Ok(())
    }

    fn remove_file_if_exists(
        &self,
        root: &Path,
        path: &Path,
        dry_run: bool,
    ) -> Result<bool, DomainError> {
        self.ensure_symlink_free_path(root, path)?;
        let existed =
            self.files.borrow().contains_key(path) || self.symlinks.borrow().contains_key(path);
        if !dry_run && existed {
            self.files.borrow_mut().remove(path);
            self.symlinks.borrow_mut().remove(path);
        }
        Ok(existed)
    }
}

struct FakeRegistry {
    apps: RefCell<Vec<InstalledApp>>,
    schema_version: RefCell<Option<u32>>,
    fail_load: bool,
    fail_save: bool,
    save_calls: RefCell<usize>,
}

impl FakeRegistry {
    fn new(initial: Vec<InstalledApp>) -> Self {
        Self {
            apps: RefCell::new(initial),
            schema_version: RefCell::new(Some(2)),
            fail_load: false,
            fail_save: false,
            save_calls: RefCell::new(0),
        }
    }

    fn with_schema_version(initial: Vec<InstalledApp>, schema_version: Option<u32>) -> Self {
        Self {
            apps: RefCell::new(initial),
            schema_version: RefCell::new(schema_version),
            fail_load: false,
            fail_save: false,
            save_calls: RefCell::new(0),
        }
    }
}

impl RegistryPort for FakeRegistry {
    fn load(&self, layout: &XdgLayout) -> Result<Vec<InstalledApp>, DomainError> {
        if self.fail_load {
            return Err(DomainError::RegistryCorrupted {
                path: layout.registry_path.clone(),
                reason: "invalid json".to_string(),
            });
        }
        Ok(self.apps.borrow().clone())
    }

    fn load_with_meta(&self, layout: &XdgLayout) -> Result<LoadedRegistry, DomainError> {
        let apps = self.load(layout)?;
        Ok(LoadedRegistry {
            schema_version: *self.schema_version.borrow(),
            apps,
        })
    }

    fn save(
        &self,
        _layout: &XdgLayout,
        apps: &[InstalledApp],
        dry_run: bool,
    ) -> Result<(), DomainError> {
        if self.fail_save {
            return Err(DomainError::Io {
                context: "saving registry".to_string(),
                reason: "permission denied".to_string(),
            });
        }
        if !dry_run {
            *self.save_calls.borrow_mut() += 1;
            *self.apps.borrow_mut() = apps.to_vec();
            *self.schema_version.borrow_mut() = Some(2);
        }
        Ok(())
    }
}

struct StubCache {
    validate_warnings: Vec<String>,
    refresh_calls: RefCell<usize>,
}

impl StubCache {
    fn new() -> Self {
        Self {
            validate_warnings: Vec::new(),
            refresh_calls: RefCell::new(0),
        }
    }
}

impl DesktopCachePort for StubCache {
    fn validate_desktop_file(&self, _desktop_path: &Path) -> Vec<String> {
        self.validate_warnings.clone()
    }

    fn refresh_desktop_caches(
        &self,
        _layout: &XdgLayout,
        dry_run: bool,
    ) -> Vec<CacheRefreshOutcome> {
        *self.refresh_calls.borrow_mut() += 1;
        vec![CacheRefreshOutcome {
            tool: "update-desktop-database".to_string(),
            executed: !dry_run,
            detail: if dry_run {
                "would run".to_string()
            } else {
                "updated".to_string()
            },
        }]
    }
}

struct StubProbe(DoctorReport);

impl SystemProbePort for StubProbe {
    fn probe_environment(&self, _layout: &XdgLayout) -> DoctorReport {
        self.0.clone()
    }
}

fn test_layout() -> XdgLayout {
    XdgLayout::try_from_env_values(Path::new("/home/tester"), None).unwrap()
}

fn sample_inspected() -> InspectedAppImage {
    InspectedAppImage {
        metadata: ExtractedMetadata {
            app_name: "Obsidian".to_string(),
            version: Some("1.7.4".to_string()),
            generic_name: Some("Knowledge Base".to_string()),
            comment: Some("Markdown notes".to_string()),
            icon_key: Some("obsidian".to_string()),
            categories: vec!["Office".to_string(), "Utility".to_string()],
            mime_types: vec!["x-scheme-handler/obsidian".to_string()],
            keywords: vec!["notes".to_string()],
            startup_wm_class: Some("obsidian".to_string()),
            terminal: false,
            startup_notify: Some(true),
            exec_field_code: Some(DesktopFieldCode::UpperU),
            icons: vec![
                ExtractedIcon {
                    size_dir: "256x256".to_string(),
                    format: IconFormat::Png,
                    bytes: vec![0x89, b'P', b'N', b'G'],
                },
                ExtractedIcon {
                    size_dir: "scalable".to_string(),
                    format: IconFormat::Svg,
                    bytes: b"<svg></svg>".to_vec(),
                },
            ],
        },
        sha256: "deadbeef".repeat(8),
    }
}

fn sample_installed_app(layout: &XdgLayout, slug_str: &str, name: &str) -> InstalledApp {
    let slug = AppSlug::parse_strict(slug_str).unwrap();
    InstalledApp {
        slug: slug.clone(),
        name: name.to_string(),
        version: Some("1.0.0".to_string()),
        appimage_path: layout
            .applications_dir
            .join(format!("{name}-1.0.0.AppImage")),
        stable_symlink_path: Some(layout.applications_dir.join(format!("{slug_str}.AppImage"))),
        cli_symlink_path: Some(layout.bin_dir.join(slug_str)),
        desktop_file_path: layout
            .desktop_entries_dir
            .join(format!("{slug_str}.desktop")),
        icon_paths: vec![
            layout
                .icons_hicolor_dir
                .join("128x128")
                .join("apps")
                .join(format!("{slug_str}.png")),
        ],
        sha256: "abc".to_string(),
        desktop_file_sha256: None,
        icon_sha256s: BTreeMap::new(),
        installed_at: "2026-11-21T10:00:00Z".to_string(),
    }
}

#[test]
fn install_fails_on_extractor_error_corrupted_registry_or_save_error() {
    let layout = test_layout();
    let src = PathBuf::from("/tmp/Obsidian-1.7.4.AppImage");
    let fs = FakeFs::new();
    fs.insert_file(&src, b"ELF");
    let registry = FakeRegistry::new(Vec::new());
    let cache = StubCache::new();
    let clock = StubClock("2026-11-21T12:00:00Z");

    let failing_extractor = MockExtractor {
        result: Err(DomainError::InvalidAppImage {
            path: src.clone(),
            reason: "bad squashfs".to_string(),
        }),
    };
    let uc = InstallUseCase::new(&failing_extractor, &fs, &registry, &cache, &clock);
    let err = uc
        .execute(
            &layout,
            &InstallOptions {
                source_path: src.clone(),
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            },
        )
        .unwrap_err();
    assert!(matches!(err, DomainError::InvalidAppImage { .. }));
    assert_eq!(*registry.save_calls.borrow(), 0);

    let ok_extractor = MockExtractor {
        result: Ok(sample_inspected()),
    };
    let mut corrupted_registry = FakeRegistry::new(Vec::new());
    corrupted_registry.fail_load = true;
    let uc_reg = InstallUseCase::new(&ok_extractor, &fs, &corrupted_registry, &cache, &clock);
    assert!(matches!(
        uc_reg.execute(
            &layout,
            &InstallOptions {
                source_path: src.clone(),
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            }
        ),
        Err(DomainError::RegistryCorrupted { .. })
    ));

    let mut failing_save_reg = FakeRegistry::new(Vec::new());
    failing_save_reg.fail_save = true;
    let uc_save = InstallUseCase::new(&ok_extractor, &fs, &failing_save_reg, &cache, &clock);
    assert!(matches!(
        uc_save.execute(
            &layout,
            &InstallOptions {
                source_path: src,
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            }
        ),
        Err(DomainError::Io { .. })
    ));
}

#[test]
fn install_rejects_missing_symlink_source_invalid_slug_symlink_dir_and_cross_app_collisions() {
    let layout = test_layout();
    let fs = FakeFs::new();
    let registry = FakeRegistry::new(Vec::new());
    let cache = StubCache::new();
    let clock = StubClock("2026-11-21T12:00:00Z");
    let extractor = MockExtractor {
        result: Ok(sample_inspected()),
    };
    let uc = InstallUseCase::new(&extractor, &fs, &registry, &cache, &clock);

    assert!(matches!(
        uc.execute(
            &layout,
            &InstallOptions {
                source_path: PathBuf::from("/tmp/missing.AppImage"),
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            }
        ),
        Err(DomainError::InputFileNotFound(_))
    ));

    let symlink_src = PathBuf::from("/tmp/symlink.AppImage");
    fs.symlinks
        .borrow_mut()
        .insert(symlink_src.clone(), PathBuf::from("/etc/passwd"));
    assert!(matches!(
        uc.execute(
            &layout,
            &InstallOptions {
                source_path: symlink_src,
                move_source: true,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            }
        ),
        Err(DomainError::NotARegularFile(_))
    ));

    let src = PathBuf::from("/tmp/Obsidian-1.7.4.AppImage");
    fs.insert_file(&src, b"ELF");

    assert!(matches!(
        uc.execute(
            &layout,
            &InstallOptions {
                source_path: src.clone(),
                move_source: false,
                custom_name: Some("---".to_string()),
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            }
        ),
        Err(DomainError::InvalidSlug(_))
    ));

    fs.symlink_dirs
        .borrow_mut()
        .insert(layout.icons_hicolor_dir.join("256x256"));
    assert!(matches!(
        uc.execute(
            &layout,
            &InstallOptions {
                source_path: src.clone(),
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            }
        ),
        Err(DomainError::UnsafeManagedPath(_))
    ));
    fs.symlink_dirs.borrow_mut().clear();

    fs.insert_file(&layout.bin_dir.join("obsidian"), b"foreign binary");
    assert!(matches!(
        uc.execute(
            &layout,
            &InstallOptions {
                source_path: src.clone(),
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            }
        ),
        Err(DomainError::CollisionDetected { .. })
    ));

    let force_summary = uc
        .execute(
            &layout,
            &InstallOptions {
                source_path: src.clone(),
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: true,
                dry_run: false,
                expected_sha256: None,
            },
        )
        .unwrap();
    assert!(!force_summary.warnings.is_empty());

    let cross_app_err = uc
        .execute(
            &layout,
            &InstallOptions {
                source_path: src,
                move_source: false,
                custom_name: Some("Obsidian Beta".to_string()),
                no_cli: false,
                force: true,
                dry_run: false,
                expected_sha256: None,
            },
        )
        .unwrap_err();
    assert!(matches!(
        cross_app_err,
        DomainError::CollisionDetected { .. }
    ));
}

#[test]
fn uninstall_rejects_missing_ambiguous_and_tampered_paths() {
    let layout = test_layout();
    let fs = FakeFs::new();
    let cache = StubCache::new();

    let empty_registry = FakeRegistry::new(Vec::new());
    let uc_empty = UninstallUseCase::new(&fs, &empty_registry, &cache);
    assert!(matches!(
        uc_empty.execute(
            &layout,
            &UninstallOptions {
                target: "obsidian".to_string(),
                dry_run: false,
            }
        ),
        Err(DomainError::AppNotInstalled(_))
    ));

    let mut tampered = sample_installed_app(&layout, "evil", "Evil");
    tampered
        .icon_paths
        .push(layout.desktop_entries_dir.join("mimeapps.list"));
    let tampered_registry = FakeRegistry::new(vec![tampered]);
    let uc_tampered = UninstallUseCase::new(&fs, &tampered_registry, &cache);
    assert!(matches!(
        uc_tampered.execute(
            &layout,
            &UninstallOptions {
                target: "evil".to_string(),
                dry_run: false,
            }
        ),
        Err(DomainError::UnsafeManagedPath(_))
    ));

    let app_a = sample_installed_app(&layout, "app-a", "Duplicate");
    let app_b = sample_installed_app(&layout, "app-b", "Duplicate");
    let dup_registry = FakeRegistry::new(vec![app_a, app_b]);
    let uc_dup = UninstallUseCase::new(&fs, &dup_registry, &cache);
    assert!(matches!(
        uc_dup.execute(
            &layout,
            &UninstallOptions {
                target: "Duplicate".to_string(),
                dry_run: false,
            }
        ),
        Err(DomainError::AmbiguousUninstallTarget { .. })
    ));
}

#[test]
fn install_dry_run_update_cleanup_no_cli_and_same_name_skip_self_symlink() {
    let layout = test_layout();
    let fs = FakeFs::new();
    let src_v1 = PathBuf::from("/tmp/Obsidian-1.7.4.AppImage");
    fs.insert_file(&src_v1, b"ELF-v1");
    let registry = FakeRegistry::new(Vec::new());
    let cache = StubCache::new();
    let clock = StubClock("2026-11-21T12:00:00Z");
    let extractor = MockExtractor {
        result: Ok(sample_inspected()),
    };
    let uc = InstallUseCase::new(&extractor, &fs, &registry, &cache, &clock);

    let dry_summary = uc
        .execute(
            &layout,
            &InstallOptions {
                source_path: src_v1.clone(),
                move_source: true,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: true,
                expected_sha256: None,
            },
        )
        .unwrap();
    assert!(dry_summary.dry_run);
    assert_eq!(*registry.save_calls.borrow(), 0);
    assert!(fs.is_regular_non_symlink_file(&src_v1));
    assert!(
        !fs.is_regular_non_symlink_file(&layout.applications_dir.join("Obsidian-1.7.4.AppImage"))
    );

    let v1_summary = uc
        .execute(
            &layout,
            &InstallOptions {
                source_path: src_v1,
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: None,
            },
        )
        .unwrap();
    assert!(!v1_summary.updated_existing);
    assert!(v1_summary.installed_app.stable_symlink_path.is_some());
    assert!(v1_summary.installed_app.cli_symlink_path.is_some());

    let mut v2_inspected = sample_inspected();
    v2_inspected.metadata.version = Some("2.0.0".to_string());
    v2_inspected.metadata.icons = vec![ExtractedIcon {
        size_dir: "scalable".to_string(),
        format: IconFormat::Svg,
        bytes: b"<svg></svg>".to_vec(),
    }];
    let v2_extractor = MockExtractor {
        result: Ok(v2_inspected),
    };
    let uc_v2 = InstallUseCase::new(&v2_extractor, &fs, &registry, &cache, &clock);
    let src_v2 = PathBuf::from("/tmp/obsidian.AppImage");
    fs.insert_file(&src_v2, b"ELF-v2");

    let v2_summary = uc_v2
        .execute(
            &layout,
            &InstallOptions {
                source_path: src_v2,
                move_source: true,
                custom_name: None,
                no_cli: true,
                force: false,
                dry_run: false,
                expected_sha256: None,
            },
        )
        .unwrap();
    assert!(v2_summary.updated_existing);
    assert_eq!(v2_summary.installed_app.stable_symlink_path, None);
    assert_eq!(v2_summary.installed_app.cli_symlink_path, None);
    let removed_set: BTreeMap<_, _> = v2_summary
        .removed_obsolete_paths
        .iter()
        .map(|p| (p.clone(), ()))
        .collect();
    assert!(removed_set.contains_key(&layout.applications_dir.join("Obsidian-1.7.4.AppImage")));
    assert!(!removed_set.contains_key(&layout.applications_dir.join("obsidian.AppImage")));
    assert!(fs.is_regular_non_symlink_file(&layout.applications_dir.join("obsidian.AppImage")));
    assert!(
        !fs.symlinks
            .borrow()
            .contains_key(&layout.applications_dir.join("obsidian.AppImage"))
    );
    assert!(removed_set.contains_key(&layout.bin_dir.join("obsidian")));
    assert!(removed_set.contains_key(&layout.icons_hicolor_dir.join("256x256/apps/obsidian.png")));
}

#[test]
fn list_and_doctor_and_uninstall_full_success() {
    let layout = test_layout();
    let fs = FakeFs::new();
    let app = sample_installed_app(&layout, "obsidian", "Obsidian");
    fs.insert_file(&app.appimage_path, b"ELF");
    fs.insert_file(&app.desktop_file_path, b"[Desktop Entry]\n");
    fs.symlinks.borrow_mut().insert(
        app.stable_symlink_path.clone().unwrap(),
        PathBuf::from("Obsidian-1.0.0.AppImage"),
    );
    fs.symlinks.borrow_mut().insert(
        app.cli_symlink_path.clone().unwrap(),
        app.stable_symlink_path.clone().unwrap(),
    );
    fs.insert_file(&app.icon_paths[0], b"PNG");

    let missing_app = sample_installed_app(&layout, "ghost", "Ghost");
    let registry = FakeRegistry::new(vec![app.clone(), missing_app]);
    let list_uc = ListUseCase::new(&fs, &registry);
    let listed = list_uc.execute(&layout).unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].app.slug.as_str(), "ghost");
    assert!(!listed[0].binary_present);
    assert_eq!(listed[1].app.slug.as_str(), "obsidian");
    assert!(listed[1].binary_present);
    assert!(listed[1].desktop_present);

    let cache = StubCache::new();
    let uninstall_uc = UninstallUseCase::new(&fs, &registry, &cache);
    let dry_u = uninstall_uc
        .execute(
            &layout,
            &UninstallOptions {
                target: "Obsidian-1.0.0.AppImage".to_string(),
                dry_run: true,
            },
        )
        .unwrap();
    assert!(dry_u.dry_run);
    assert!(fs.is_regular_non_symlink_file(&app.appimage_path));

    let real_u = uninstall_uc
        .execute(
            &layout,
            &UninstallOptions {
                target: "Obsidian".to_string(),
                dry_run: false,
            },
        )
        .unwrap();
    assert!(!real_u.dry_run);
    assert!(!fs.path_or_symlink_exists(&app.appimage_path));
    assert!(!fs.path_or_symlink_exists(&app.desktop_file_path));
    assert_eq!(registry.apps.borrow().len(), 1);

    let probe = StubProbe(DoctorReport {
        checks: vec![DoctorCheck {
            name: "libfuse3".to_string(),
            status: DoctorCheckStatus::Ok,
            detail: "ok".to_string(),
            pacman_package: None,
            remediation: None,
        }],
        missing_pacman_packages: Vec::new(),
        healthy: true,
    });
    let doctor_uc = DoctorUseCase::new(&probe);
    let report = doctor_uc.execute(&layout);
    assert!(report.healthy);
}

#[test]
fn install_expected_sha256_and_verify_use_case_cover_all_error_and_success_branches() {
    let layout = test_layout();
    let src = PathBuf::from("/tmp/Verified-1.0.AppImage");
    let fs = FakeFs::new();
    fs.insert_file(&src, b"ELF-verified");
    let registry = FakeRegistry::new(Vec::new());
    let cache = StubCache::new();
    let clock = StubClock("2026-11-21T12:00:00Z");
    let inspected = sample_inspected();
    let expected_hex = inspected.sha256.clone();
    let extractor = MockExtractor {
        result: Ok(inspected),
    };
    let install_uc = InstallUseCase::new(&extractor, &fs, &registry, &cache, &clock);

    assert!(matches!(
        install_uc.execute(
            &layout,
            &InstallOptions {
                source_path: src.clone(),
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: Some("not-hex".to_string()),
            }
        ),
        Err(DomainError::InvalidSha256(_))
    ));

    let wrong_hex = "0".repeat(64);
    assert!(matches!(
        install_uc.execute(
            &layout,
            &InstallOptions {
                source_path: src.clone(),
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: false,
                expected_sha256: Some(wrong_hex),
            }
        ),
        Err(DomainError::Sha256Mismatch { .. })
    ));
    assert_eq!(*registry.save_calls.borrow(), 0);

    let ok_install = install_uc
        .execute(
            &layout,
            &InstallOptions {
                source_path: src,
                move_source: false,
                custom_name: None,
                no_cli: false,
                force: false,
                dry_run: true,
                expected_sha256: Some(expected_hex.to_ascii_uppercase()),
            },
        )
        .unwrap();
    assert!(ok_install.dry_run);

    let mut failing_reg = FakeRegistry::new(Vec::new());
    failing_reg.fail_load = true;
    let verify_err_uc = VerifyUseCase::new(&fs, &failing_reg);
    assert!(matches!(
        verify_err_uc.execute(
            &layout,
            &VerifyOptions {
                target: None,
                strict: false,
            }
        ),
        Err(DomainError::RegistryCorrupted { .. })
    ));

    let empty_reg = FakeRegistry::new(Vec::new());
    let verify_empty_uc = VerifyUseCase::new(&fs, &empty_reg);
    let empty_report = verify_empty_uc
        .execute(
            &layout,
            &VerifyOptions {
                target: None,
                strict: false,
            },
        )
        .unwrap();
    assert!(empty_report.all_ok);
    assert!(empty_report.entries.is_empty());
    assert!(matches!(
        verify_empty_uc.execute(
            &layout,
            &VerifyOptions {
                target: Some("ghost".to_string()),
                strict: false,
            }
        ),
        Err(DomainError::AppNotInstalled(_))
    ));

    let mut ok_app = sample_installed_app(&layout, "good", "Good");
    let good_bytes = b"GOOD-APPIMAGE".to_vec();
    ok_app.sha256 = hex::encode(Sha256::digest(&good_bytes));
    fs.insert_file(&ok_app.appimage_path, &good_bytes);

    let mut mismatch_app = sample_installed_app(&layout, "tampered", "Tampered");
    mismatch_app.sha256 = "f".repeat(64);
    fs.insert_file(&mismatch_app.appimage_path, b"MODIFIED");

    let mut missing_app = sample_installed_app(&layout, "missing", "Missing");
    missing_app.sha256 = "e".repeat(64);

    let mut sym_app = sample_installed_app(&layout, "symlinked", "Symlinked");
    sym_app.sha256 = "d".repeat(64);
    fs.symlinks
        .borrow_mut()
        .insert(sym_app.appimage_path.clone(), PathBuf::from("/etc/passwd"));

    let mut unsafe_app = sample_installed_app(&layout, "outside", "Outside");
    unsafe_app.appimage_path = PathBuf::from("/etc/passwd");
    unsafe_app.sha256 = "c".repeat(64);

    let bad_hash_app = sample_installed_app(&layout, "badhash", "BadHash");

    let verify_reg = FakeRegistry::new(vec![
        ok_app,
        mismatch_app,
        missing_app,
        sym_app,
        unsafe_app,
        bad_hash_app,
    ]);
    let verify_uc = VerifyUseCase::new(&fs, &verify_reg);

    let report = verify_uc
        .execute(
            &layout,
            &VerifyOptions {
                target: None,
                strict: false,
            },
        )
        .unwrap();
    assert!(!report.all_ok);
    assert_eq!(report.entries.len(), 6);
    assert_eq!(
        report
            .entries
            .iter()
            .find(|e| e.slug.as_str() == "good")
            .unwrap()
            .status,
        VerifyEntryStatus::Ok
    );
    assert_eq!(
        report
            .entries
            .iter()
            .find(|e| e.slug.as_str() == "tampered")
            .unwrap()
            .status,
        VerifyEntryStatus::Sha256Mismatch
    );
    assert_eq!(
        report
            .entries
            .iter()
            .find(|e| e.slug.as_str() == "missing")
            .unwrap()
            .status,
        VerifyEntryStatus::Missing
    );
    assert_eq!(
        report
            .entries
            .iter()
            .find(|e| e.slug.as_str() == "symlinked")
            .unwrap()
            .status,
        VerifyEntryStatus::NotRegularFile
    );
    assert_eq!(
        report
            .entries
            .iter()
            .find(|e| e.slug.as_str() == "outside")
            .unwrap()
            .status,
        VerifyEntryStatus::UnsafePath
    );
    assert_eq!(
        report
            .entries
            .iter()
            .find(|e| e.slug.as_str() == "badhash")
            .unwrap()
            .status,
        VerifyEntryStatus::Error
    );

    let single_ok = verify_uc
        .execute(
            &layout,
            &VerifyOptions {
                target: Some("good".to_string()),
                strict: false,
            },
        )
        .unwrap();
    assert!(single_ok.all_ok);
    assert_eq!(single_ok.entries.len(), 1);
}

#[test]
fn verify_strict_audits_desktop_symlinks_and_icons() {
    let layout = test_layout();
    let fs = FakeFs::new();
    let mut app = sample_installed_app(&layout, "strictapp", "StrictApp");
    let app_bytes = b"STRICT-BIN".to_vec();
    app.sha256 = hex::encode(Sha256::digest(&app_bytes));

    fs.insert_file(&app.appimage_path, &app_bytes);
    fs.insert_file(&app.desktop_file_path, b"[Desktop Entry]\n");
    fs.symlinks.borrow_mut().insert(
        app.stable_symlink_path.clone().unwrap(),
        PathBuf::from("StrictApp-1.0.AppImage"),
    );
    fs.symlinks.borrow_mut().insert(
        app.cli_symlink_path.clone().unwrap(),
        app.stable_symlink_path.clone().unwrap(),
    );
    fs.insert_file(&app.icon_paths[0], b"PNG");

    let registry = FakeRegistry::new(vec![app.clone()]);
    let verify_uc = VerifyUseCase::new(&fs, &registry);

    let bad_stable = verify_uc
        .execute(
            &layout,
            &VerifyOptions {
                target: None,
                strict: true,
            },
        )
        .unwrap();
    assert!(!bad_stable.all_ok);
    assert_eq!(
        bad_stable.entries[0].status,
        VerifyEntryStatus::ArtifactError
    );

    fs.symlinks.borrow_mut().insert(
        app.stable_symlink_path.clone().unwrap(),
        PathBuf::from("StrictApp-1.0.0.AppImage"),
    );
    let ok_strict = verify_uc
        .execute(
            &layout,
            &VerifyOptions {
                target: None,
                strict: true,
            },
        )
        .unwrap();
    assert!(ok_strict.all_ok);
    assert_eq!(ok_strict.entries[0].status, VerifyEntryStatus::Ok);
    assert_eq!(ok_strict.entries[0].artifact_checks.len(), 4);
    assert!(ok_strict.entries[0].artifact_checks.iter().all(|c| c.ok));

    fs.files.borrow_mut().remove(&app.desktop_file_path);
    fs.symlinks.borrow_mut().insert(
        app.cli_symlink_path.clone().unwrap(),
        PathBuf::from("/bin/sh"),
    );
    fs.files.borrow_mut().remove(&app.icon_paths[0]);

    let failed_strict = verify_uc
        .execute(
            &layout,
            &VerifyOptions {
                target: Some("strictapp".to_string()),
                strict: true,
            },
        )
        .unwrap();
    assert!(!failed_strict.all_ok);
    assert_eq!(
        failed_strict.entries[0].status,
        VerifyEntryStatus::ArtifactError
    );
    assert!(
        !failed_strict.entries[0]
            .artifact_checks
            .iter()
            .find(|c| c.kind == "desktop")
            .unwrap()
            .ok
    );
    assert!(
        !failed_strict.entries[0]
            .artifact_checks
            .iter()
            .find(|c| c.kind == "cli_symlink")
            .unwrap()
            .ok
    );
    assert!(
        !failed_strict.entries[0]
            .artifact_checks
            .iter()
            .find(|c| c.kind == "icon")
            .unwrap()
            .ok
    );

    let desktop_bytes = b"[Desktop Entry]\nType=Application\nName=StrictApp\n".to_vec();
    let icon_bytes = b"PNG-VALID".to_vec();
    fs.insert_file(&app.desktop_file_path, &desktop_bytes);
    fs.symlinks.borrow_mut().insert(
        app.cli_symlink_path.clone().unwrap(),
        app.stable_symlink_path.clone().unwrap(),
    );
    fs.insert_file(&app.icon_paths[0], &icon_bytes);

    let mut v2_app = app.clone();
    v2_app.desktop_file_sha256 = Some(hex::encode(Sha256::digest(&desktop_bytes)));
    v2_app.icon_sha256s.insert(
        app.icon_paths[0].to_string_lossy().into_owned(),
        hex::encode(Sha256::digest(&icon_bytes)),
    );

    let v2_reg = FakeRegistry::new(vec![v2_app]);
    let v2_verify = VerifyUseCase::new(&fs, &v2_reg);
    let v2_ok = v2_verify
        .execute(
            &layout,
            &VerifyOptions {
                target: None,
                strict: true,
            },
        )
        .unwrap();
    assert!(v2_ok.all_ok);
    assert_eq!(v2_ok.entries[0].status, VerifyEntryStatus::Ok);

    fs.insert_file(&app.desktop_file_path, b"[Desktop Entry]\nExec=evil\n");
    fs.insert_file(&app.icon_paths[0], b"PNG-TAMPERED");

    let v2_tampered = v2_verify
        .execute(
            &layout,
            &VerifyOptions {
                target: None,
                strict: true,
            },
        )
        .unwrap();
    assert!(!v2_tampered.all_ok);
    assert_eq!(
        v2_tampered.entries[0].status,
        VerifyEntryStatus::ArtifactError
    );
    let desktop_art = v2_tampered.entries[0]
        .artifact_checks
        .iter()
        .find(|c| c.kind == "desktop")
        .unwrap();
    assert!(!desktop_art.ok);
    assert!(desktop_art.detail.contains("checksum mismatch"));
    let icon_art = v2_tampered.entries[0]
        .artifact_checks
        .iter()
        .find(|c| c.kind == "icon")
        .unwrap();
    assert!(!icon_art.ok);
    assert!(icon_art.detail.contains("checksum mismatch"));
}

#[test]
fn verify_strict_rejects_in_memory_non_canonical_paths_and_icon_hash_bypass() {
    let layout = test_layout();
    let fs = FakeFs::new();
    let app = sample_installed_app(&layout, "strictapp", "StrictApp");
    let app_bytes = b"STRICT-BIN".to_vec();
    let desktop_bytes = b"[Desktop Entry]\nType=Application\nName=StrictApp\n".to_vec();

    let mut base_app = app.clone();
    base_app.sha256 = hex::encode(Sha256::digest(&app_bytes));
    base_app.desktop_file_sha256 = Some(hex::encode(Sha256::digest(&desktop_bytes)));

    fs.insert_file(&base_app.appimage_path, &app_bytes);
    fs.insert_file(&base_app.desktop_file_path, &desktop_bytes);
    fs.symlinks.borrow_mut().insert(
        base_app.stable_symlink_path.clone().unwrap(),
        PathBuf::from("StrictApp-1.0.0.AppImage"),
    );
    fs.symlinks.borrow_mut().insert(
        base_app.cli_symlink_path.clone().unwrap(),
        base_app.stable_symlink_path.clone().unwrap(),
    );
    fs.insert_file(&base_app.icon_paths[0], b"TAMPERED-ICON");

    let non_canonical_keys = [
        format!(
            "{}/128x128/apps/./strictapp.png",
            layout.icons_hicolor_dir.display()
        ),
        format!(
            "{}/128x128//apps/strictapp.png",
            layout.icons_hicolor_dir.display()
        ),
        format!(
            "{}/128x128/apps/strictapp.png/",
            layout.icons_hicolor_dir.display()
        ),
    ];

    for bad_key in &non_canonical_keys {
        let mut crafted = base_app.clone();
        crafted.icon_sha256s.insert(bad_key.clone(), "f".repeat(64));

        let registry = FakeRegistry::new(vec![crafted]);
        let verify_uc = VerifyUseCase::new(&fs, &registry);
        let report = verify_uc
            .execute(
                &layout,
                &VerifyOptions {
                    target: None,
                    strict: true,
                },
            )
            .unwrap();
        assert!(!report.all_ok);
        assert_eq!(report.entries[0].status, VerifyEntryStatus::UnsafePath);

        let mut dup_key_app = base_app.clone();
        dup_key_app.icon_sha256s.insert(
            base_app.icon_paths[0].to_string_lossy().into_owned(),
            hex::encode(Sha256::digest(b"EXPECTED-ICON")),
        );
        dup_key_app.icon_sha256s.insert(
            bad_key.clone(),
            hex::encode(Sha256::digest(b"TAMPERED-ICON")),
        );
        let dup_reg = FakeRegistry::new(vec![dup_key_app]);
        let dup_verify = VerifyUseCase::new(&fs, &dup_reg);
        let dup_report = dup_verify
            .execute(
                &layout,
                &VerifyOptions {
                    target: None,
                    strict: true,
                },
            )
            .unwrap();
        assert!(!dup_report.all_ok);
        assert_eq!(dup_report.entries[0].status, VerifyEntryStatus::UnsafePath);
    }

    let mut non_canonical_icon_path_app = base_app;
    non_canonical_icon_path_app.icon_paths = vec![PathBuf::from(non_canonical_keys[2].clone())];
    let trailing_reg = FakeRegistry::new(vec![non_canonical_icon_path_app]);
    let trailing_verify = VerifyUseCase::new(&fs, &trailing_reg);
    let trailing_report = trailing_verify
        .execute(
            &layout,
            &VerifyOptions {
                target: None,
                strict: true,
            },
        )
        .unwrap();
    assert!(!trailing_report.all_ok);
    assert_eq!(
        trailing_report.entries[0].status,
        VerifyEntryStatus::UnsafePath
    );
}

#[test]
fn migrate_registry_upgrades_v1_preserves_existing_hashes_and_fails_closed() {
    let layout = test_layout();
    let fs = FakeFs::new();
    let mut app_a = sample_installed_app(&layout, "alpha", "Alpha");
    app_a.sha256 = "a".repeat(64);
    let mut app_b = sample_installed_app(&layout, "beta", "Beta");
    app_b.sha256 = "b".repeat(64);
    let preset_desktop_sha = "c".repeat(64);
    app_b.desktop_file_sha256 = Some(preset_desktop_sha.clone());

    let desktop_a_bytes = b"[Desktop Entry]\nType=Application\nName=Alpha\n";
    let icon_a_bytes = b"ALPHA-PNG";
    let desktop_b_bytes = b"[Desktop Entry]\nType=Application\nName=Beta-Original\n";
    let icon_b_bytes = b"BETA-PNG";

    fs.insert_file(&app_a.desktop_file_path, desktop_a_bytes);
    fs.insert_file(&app_a.icon_paths[0], icon_a_bytes);
    fs.insert_file(&app_b.desktop_file_path, desktop_b_bytes);
    fs.insert_file(&app_b.icon_paths[0], icon_b_bytes);

    let registry = FakeRegistry::with_schema_version(vec![app_b.clone(), app_a.clone()], Some(1));
    let migrate_uc = MigrateRegistryUseCase::new(&fs, &registry);

    let dry = migrate_uc
        .execute(&layout, &MigrateRegistryOptions { dry_run: true })
        .unwrap();
    assert!(dry.dry_run);
    assert!(!dry.registry_written);
    assert!(!dry.already_up_to_date);
    assert_eq!(dry.previous_schema_version, Some(1));
    assert_eq!(dry.migrated_count, 2);
    assert_eq!(dry.failed_count, 0);
    assert_eq!(*registry.save_calls.borrow(), 0);

    let real = migrate_uc
        .execute(&layout, &MigrateRegistryOptions { dry_run: false })
        .unwrap();
    assert!(!real.dry_run);
    assert!(real.registry_written);
    assert!(!real.already_up_to_date);
    assert_eq!(real.migrated_count, 2);
    assert_eq!(real.failed_count, 0);
    assert_eq!(*registry.save_calls.borrow(), 1);
    assert_eq!(*registry.schema_version.borrow(), Some(2));

    let saved = registry.apps.borrow().clone();
    assert_eq!(saved[0].slug.as_str(), "alpha");
    assert_eq!(
        saved[0].desktop_file_sha256.as_deref(),
        Some(hex::encode(Sha256::digest(desktop_a_bytes)).as_str())
    );
    assert_eq!(
        saved[0]
            .icon_sha256s
            .get(app_a.icon_paths[0].to_str().unwrap())
            .map(String::as_str),
        Some(hex::encode(Sha256::digest(icon_a_bytes)).as_str())
    );
    assert_eq!(saved[1].slug.as_str(), "beta");
    assert_eq!(
        saved[1].desktop_file_sha256.as_deref(),
        Some(preset_desktop_sha.as_str())
    );
    assert_eq!(
        saved[1]
            .icon_sha256s
            .get(app_b.icon_paths[0].to_str().unwrap())
            .map(String::as_str),
        Some(hex::encode(Sha256::digest(icon_b_bytes)).as_str())
    );

    let second = migrate_uc
        .execute(&layout, &MigrateRegistryOptions { dry_run: false })
        .unwrap();
    assert!(second.already_up_to_date);
    assert!(!second.registry_written);
    assert_eq!(second.unchanged_count, 2);
    assert_eq!(*registry.save_calls.borrow(), 1);

    fs.files.borrow_mut().remove(&app_b.icon_paths[0]);
    let partial_fail_reg =
        FakeRegistry::with_schema_version(vec![app_a.clone(), app_b.clone()], Some(1));
    let partial_uc = MigrateRegistryUseCase::new(&fs, &partial_fail_reg);
    let partial_res = partial_uc
        .execute(&layout, &MigrateRegistryOptions { dry_run: false })
        .unwrap();
    assert!(!partial_res.registry_written);
    assert_eq!(partial_res.migrated_count, 1);
    assert_eq!(partial_res.failed_count, 1);
    assert_eq!(
        partial_res.entries[1].status,
        MigrateRegistryEntryStatus::Error
    );
    assert_eq!(*partial_fail_reg.save_calls.borrow(), 0);
    assert_eq!(*partial_fail_reg.schema_version.borrow(), Some(1));
    assert!(
        partial_fail_reg.apps.borrow()[0]
            .desktop_file_sha256
            .is_none()
    );
}

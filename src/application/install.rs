use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::domain::desktop_entry::render_desktop_entry;
use crate::domain::error::DomainError;
use crate::domain::models::{
    ExtractedIcon, InstallOptions, InstallSummary, InstalledApp, XdgLayout, validate_sha256_hex,
};
use crate::domain::path_safety::{
    root_for_managed_path, sanitize_appimage_filename, validate_installed_app_against_layout,
};
use crate::domain::ports::{
    AppImageExtractorPort, ClockPort, DesktopCachePort, FileSystemPort, RegistryPort,
    collect_owned_paths,
};
use crate::domain::sanitizer::sanitize_single_line_value;
use crate::domain::slug::AppSlug;

pub struct InstallUseCase<'a> {
    extractor: &'a dyn AppImageExtractorPort,
    fs: &'a dyn FileSystemPort,
    registry: &'a dyn RegistryPort,
    desktop_cache: &'a dyn DesktopCachePort,
    clock: &'a dyn ClockPort,
}

impl<'a> InstallUseCase<'a> {
    pub fn new(
        extractor: &'a dyn AppImageExtractorPort,
        fs: &'a dyn FileSystemPort,
        registry: &'a dyn RegistryPort,
        desktop_cache: &'a dyn DesktopCachePort,
        clock: &'a dyn ClockPort,
    ) -> Self {
        Self {
            extractor,
            fs,
            registry,
            desktop_cache,
            clock,
        }
    }

    pub fn execute(
        &self,
        layout: &XdgLayout,
        options: &InstallOptions,
    ) -> Result<InstallSummary, DomainError> {
        if !self.fs.path_or_symlink_exists(&options.source_path) {
            return Err(DomainError::InputFileNotFound(options.source_path.clone()));
        }
        if !self.fs.is_regular_non_symlink_file(&options.source_path) {
            return Err(DomainError::NotARegularFile(options.source_path.clone()));
        }

        let normalized_expected_sha256 = options
            .expected_sha256
            .as_deref()
            .map(validate_sha256_hex)
            .transpose()?;

        let inspected = self
            .extractor
            .inspect_and_extract(&options.source_path, normalized_expected_sha256.as_deref())?;
        let mut metadata = inspected.metadata;
        let sha256 = inspected.sha256;

        if let Some(ref expected) = normalized_expected_sha256
            && &sha256 != expected
        {
            return Err(DomainError::Sha256Mismatch {
                path: options.source_path.clone(),
                expected: expected.clone(),
                actual: sha256,
            });
        }

        let display_name = resolve_display_name(
            options.custom_name.as_deref(),
            &metadata.app_name,
            &options.source_path,
        )?;
        metadata.app_name = display_name.clone();
        let slug = AppSlug::from_name_or_filename(&display_name)?;

        let raw_filename = options
            .source_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| DomainError::InvalidAppImage {
                path: options.source_path.clone(),
                reason: "source AppImage path has invalid UTF-8 filename".to_string(),
            })?;
        let sanitized_filename = sanitize_appimage_filename(raw_filename)?;
        let appimage_path = layout.applications_dir.join(&sanitized_filename);

        let stable_filename = format!("{}.AppImage", slug.as_str());
        let stable_symlink_path = if sanitized_filename == stable_filename {
            None
        } else {
            Some(layout.applications_dir.join(&stable_filename))
        };

        let exec_target = stable_symlink_path.as_ref().unwrap_or(&appimage_path);
        let cli_symlink_path = if options.no_cli {
            None
        } else {
            Some(layout.bin_dir.join(slug.as_str()))
        };
        let desktop_file_path = layout
            .desktop_entries_dir
            .join(format!("{}.desktop", slug.as_str()));

        let planned_icons = deduplicate_icons(&metadata.icons);
        let mut icon_paths = Vec::with_capacity(planned_icons.len());
        for icon in &planned_icons {
            let icon_path = layout
                .icons_hicolor_dir
                .join(&icon.size_dir)
                .join("apps")
                .join(format!("{}.{}", slug.as_str(), icon.format.extension()));
            icon_paths.push(icon_path);
        }

        let mut existing_apps = self.registry.load(layout)?;
        let previous_app = existing_apps.iter().find(|app| app.slug == slug).cloned();
        let owned_by_this: HashSet<PathBuf> = previous_app
            .as_ref()
            .map(|app| collect_owned_paths(app).into_iter().collect())
            .unwrap_or_default();

        let same_source_and_dest = self.fs.same_file(&options.source_path, &appimage_path)?;

        let mut new_paths = Vec::with_capacity(4 + icon_paths.len());
        new_paths.push(appimage_path.clone());
        if let Some(ref stable) = stable_symlink_path {
            new_paths.push(stable.clone());
        }
        if let Some(ref cli) = cli_symlink_path {
            new_paths.push(cli.clone());
        }
        new_paths.push(desktop_file_path.clone());
        new_paths.extend(icon_paths.iter().cloned());

        let roots = layout.managed_roots();
        for path in &new_paths {
            let root = root_for_managed_path(path, &roots)
                .ok_or_else(|| DomainError::UnsafeManagedPath(path.clone()))?;
            self.fs.ensure_symlink_free_path(root, path)?;
        }

        let mut warnings = Vec::new();
        for path in &new_paths {
            if let Some(owner) = existing_apps
                .iter()
                .find(|app| app.slug != slug && collect_owned_paths(app).contains(path))
            {
                return Err(DomainError::CollisionDetected {
                    path: path.clone(),
                    reason: format!(
                        "managed by installed app '{}'; uninstall it first with 'install-appimage -u {}'",
                        owner.slug.as_str(),
                        owner.slug.as_str()
                    ),
                });
            }

            if !owned_by_this.contains(path)
                && self.fs.path_or_symlink_exists(path)
                && !(path == &appimage_path && same_source_and_dest)
            {
                if !options.force {
                    return Err(DomainError::CollisionDetected {
                        path: path.clone(),
                        reason: "existing unmanaged file on disk; pass --force to overwrite"
                            .to_string(),
                    });
                }
                warnings.push(format!(
                    "Overwriting existing unmanaged file due to --force: {}",
                    path.display()
                ));
            }
        }

        let icon_field = if planned_icons.is_empty() {
            warnings.push(
                "No icon found inside AppImage; desktop entry will use generic icon 'application-x-executable'"
                    .to_string(),
            );
            "application-x-executable"
        } else {
            slug.as_str()
        };
        let desktop_contents = render_desktop_entry(&metadata, exec_target, icon_field)?;

        self.fs.create_dir_all_safe(
            &layout.applications_dir,
            &layout.applications_dir,
            options.dry_run,
        )?;
        if !options.no_cli {
            self.fs
                .create_dir_all_safe(&layout.bin_dir, &layout.bin_dir, options.dry_run)?;
        }
        self.fs.create_dir_all_safe(
            &layout.desktop_entries_dir,
            &layout.desktop_entries_dir,
            options.dry_run,
        )?;
        for icon_path in &icon_paths {
            if let Some(parent) = icon_path.parent() {
                self.fs
                    .create_dir_all_safe(&layout.icons_hicolor_dir, parent, options.dry_run)?;
            }
        }
        if let Some(reg_parent) = layout.registry_path.parent() {
            self.fs
                .create_dir_all_safe(reg_parent, reg_parent, options.dry_run)?;
        }

        self.fs.install_executable_verified(
            &options.source_path,
            &appimage_path,
            &sha256,
            options.move_source,
            options.dry_run,
        )?;

        if let Some(ref stable) = stable_symlink_path {
            self.fs.create_symlink_atomic(
                &layout.applications_dir,
                Path::new(&sanitized_filename),
                stable,
                options.dry_run,
            )?;
        }

        if let Some(ref cli) = cli_symlink_path {
            self.fs
                .create_symlink_atomic(&layout.bin_dir, exec_target, cli, options.dry_run)?;
        }

        let mut icon_sha256s = BTreeMap::new();
        for (icon, icon_path) in planned_icons.iter().zip(icon_paths.iter()) {
            self.fs.write_file_atomic(
                &layout.icons_hicolor_dir,
                icon_path,
                &icon.bytes,
                0o644,
                options.dry_run,
            )?;
            icon_sha256s.insert(
                icon_path.to_string_lossy().into_owned(),
                compute_sha256_hex(&icon.bytes),
            );
        }

        self.fs.write_file_atomic(
            &layout.desktop_entries_dir,
            &desktop_file_path,
            desktop_contents.as_bytes(),
            0o644,
            options.dry_run,
        )?;
        let desktop_file_sha256 = Some(compute_sha256_hex(desktop_contents.as_bytes()));

        if !options.dry_run {
            warnings.extend(self.desktop_cache.validate_desktop_file(&desktop_file_path));
        }

        let new_paths_set: HashSet<PathBuf> = new_paths.into_iter().collect();
        let mut removed_obsolete_paths = Vec::new();
        if let Some(ref prev) = previous_app {
            validate_installed_app_against_layout(prev, layout)?;
            for old_path in collect_owned_paths(prev) {
                if !new_paths_set.contains(&old_path) {
                    let Some(root) = root_for_managed_path(&old_path, &roots) else {
                        warnings.push(format!(
                            "Skipped cleanup of path outside managed XDG roots: {}",
                            old_path.display()
                        ));
                        continue;
                    };
                    self.fs.ensure_symlink_free_path(root, &old_path)?;
                    let existed = if options.dry_run {
                        self.fs.path_or_symlink_exists(&old_path)
                    } else {
                        self.fs.remove_file_if_exists(root, &old_path, false)?
                    };
                    if existed {
                        removed_obsolete_paths.push(old_path);
                    }
                }
            }
        }

        let installed_app = InstalledApp {
            slug: slug.clone(),
            name: display_name,
            version: metadata.version,
            appimage_path,
            stable_symlink_path,
            cli_symlink_path,
            desktop_file_path,
            icon_paths,
            sha256,
            desktop_file_sha256,
            icon_sha256s,
            installed_at: self.clock.utc_timestamp_iso8601(),
        };

        let updated_existing = previous_app.is_some();
        existing_apps.retain(|app| app.slug != slug);
        existing_apps.push(installed_app.clone());
        existing_apps.sort_by(|a, b| a.slug.cmp(&b.slug));

        self.registry
            .save(layout, &existing_apps, options.dry_run)?;

        let cache_outcomes = self
            .desktop_cache
            .refresh_desktop_caches(layout, options.dry_run);

        Ok(InstallSummary {
            dry_run: options.dry_run,
            updated_existing,
            installed_app,
            removed_obsolete_paths,
            warnings,
            cache_outcomes,
        })
    }
}

fn resolve_display_name(
    custom_name: Option<&str>,
    extracted_name: &str,
    source_path: &Path,
) -> Result<String, DomainError> {
    if let Some(raw_custom) = custom_name {
        let clean = sanitize_single_line_value(raw_custom);
        if clean.is_empty() {
            return Err(DomainError::InvalidSlug(raw_custom.to_string()));
        }
        return Ok(clean);
    }

    let clean_extracted = sanitize_single_line_value(extracted_name);
    if !clean_extracted.is_empty() {
        return Ok(clean_extracted);
    }

    let fallback = source_path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(sanitize_single_line_value)
        .unwrap_or_default();
    if fallback.is_empty() {
        return Err(DomainError::InvalidSlug(source_path.display().to_string()));
    }
    Ok(fallback)
}

fn compute_sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn deduplicate_icons(icons: &[ExtractedIcon]) -> Vec<&ExtractedIcon> {
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let mut result = Vec::with_capacity(icons.len());
    for icon in icons {
        if seen.insert((icon.size_dir.as_str(), icon.format.extension())) {
            result.push(icon);
        }
    }
    result
}

use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};

use crate::domain::error::DomainError;
use crate::domain::models::{InstalledApp, STANDARD_ICON_BUCKETS, XdgLayout, validate_sha256_hex};
use crate::domain::sanitizer::is_bidi_or_invisible_format;

const MAX_FILENAME_BYTES: usize = 255;

pub fn normalize_archive_entry_path(raw: &str) -> Result<PathBuf, DomainError> {
    if raw.is_empty()
        || raw.contains('\0')
        || raw.contains('\\')
        || raw
            .chars()
            .any(|ch| ch.is_control() || is_bidi_or_invisible_format(ch))
    {
        return Err(DomainError::UnsafePathTraversal(raw.to_string()));
    }

    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(DomainError::UnsafePathTraversal(raw.to_string()));
    }

    let mut clean = PathBuf::new();
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(part) => {
                let s = part
                    .to_str()
                    .ok_or_else(|| DomainError::UnsafePathTraversal(raw.to_string()))?;
                if s.is_empty() || (clean.as_os_str().is_empty() && is_windows_drive_like(s)) {
                    return Err(DomainError::UnsafePathTraversal(raw.to_string()));
                }
                clean.push(s);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(DomainError::UnsafePathTraversal(raw.to_string()));
            }
        }
    }

    if clean.as_os_str().is_empty() {
        return Err(DomainError::UnsafePathTraversal(raw.to_string()));
    }

    Ok(clean)
}

fn is_windows_drive_like(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

pub fn resolve_contained_symlink(
    link_path: &Path,
    raw_target: &str,
) -> Result<PathBuf, DomainError> {
    if raw_target.is_empty()
        || raw_target.contains('\0')
        || raw_target.contains('\\')
        || raw_target
            .chars()
            .any(|ch| ch.is_control() || is_bidi_or_invisible_format(ch))
    {
        return Err(DomainError::SymlinkEscape {
            link: link_path.display().to_string(),
            target: raw_target.to_string(),
        });
    }

    let mut stack: Vec<String> = if raw_target.starts_with('/') {
        Vec::new()
    } else {
        match link_path.parent() {
            Some(parent) => parent
                .components()
                .filter_map(|c| match c {
                    Component::Normal(s) => s.to_str().map(str::to_string),
                    _ => None,
                })
                .collect(),
            None => Vec::new(),
        }
    };

    for component in Path::new(raw_target).components() {
        match component {
            Component::Normal(part) => {
                let s = part.to_str().ok_or_else(|| DomainError::SymlinkEscape {
                    link: link_path.display().to_string(),
                    target: raw_target.to_string(),
                })?;
                if !s.is_empty() {
                    stack.push(s.to_string());
                }
            }
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir => {
                if stack.pop().is_none() {
                    return Err(DomainError::SymlinkEscape {
                        link: link_path.display().to_string(),
                        target: raw_target.to_string(),
                    });
                }
            }
            Component::Prefix(_) => {
                return Err(DomainError::SymlinkEscape {
                    link: link_path.display().to_string(),
                    target: raw_target.to_string(),
                });
            }
        }
    }

    if stack.is_empty() {
        return Err(DomainError::SymlinkEscape {
            link: link_path.display().to_string(),
            target: raw_target.to_string(),
        });
    }

    let mut out = PathBuf::new();
    for part in stack {
        out.push(part);
    }
    Ok(out)
}

pub fn sanitize_appimage_filename(raw_name: &str) -> Result<String, DomainError> {
    if raw_name.is_empty()
        || raw_name.contains('\0')
        || raw_name.contains('/')
        || raw_name.contains('\\')
        || raw_name == "."
        || raw_name == ".."
        || raw_name.starts_with('.')
        || raw_name.starts_with('-')
        || raw_name
            .chars()
            .any(|ch| ch.is_control() || is_bidi_or_invisible_format(ch))
    {
        return Err(DomainError::UnsafePathTraversal(raw_name.to_string()));
    }

    let normalized = if raw_name.to_ascii_lowercase().ends_with(".appimage") {
        raw_name.to_string()
    } else {
        format!("{raw_name}.AppImage")
    };

    if normalized.len() > MAX_FILENAME_BYTES {
        return Err(DomainError::InvalidSlug(raw_name.to_string()));
    }

    Ok(normalized)
}

pub fn is_strictly_inside_any(candidate: &Path, allowed_roots: &[&Path]) -> bool {
    if !candidate.is_absolute() {
        return false;
    }
    if candidate
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return false;
    }
    allowed_roots
        .iter()
        .any(|root| candidate.starts_with(root) && candidate != *root)
}

pub fn root_for_managed_path<'a>(candidate: &Path, allowed_roots: &[&'a Path]) -> Option<&'a Path> {
    if !candidate.is_absolute()
        || candidate
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return None;
    }
    allowed_roots
        .iter()
        .copied()
        .find(|root| candidate.starts_with(root) && candidate != *root)
}

pub fn validate_installed_app_against_layout(
    app: &InstalledApp,
    layout: &XdgLayout,
) -> Result<(), DomainError> {
    if app.appimage_path.parent() != Some(layout.applications_dir.as_path()) {
        return Err(DomainError::UnsafeManagedPath(app.appimage_path.clone()));
    }
    let Some(app_file) = app.appimage_path.file_name().and_then(|f| f.to_str()) else {
        return Err(DomainError::UnsafeManagedPath(app.appimage_path.clone()));
    };
    let sanitized_file = sanitize_appimage_filename(app_file)?;
    if sanitized_file != app_file {
        return Err(DomainError::UnsafeManagedPath(app.appimage_path.clone()));
    }
    let expected_appimage = layout.applications_dir.join(app_file);
    if app.appimage_path.as_os_str() != expected_appimage.as_os_str() {
        return Err(DomainError::UnsafeManagedPath(app.appimage_path.clone()));
    }

    if let Some(ref stable) = app.stable_symlink_path {
        let expected = layout
            .applications_dir
            .join(format!("{}.AppImage", app.slug.as_str()));
        if stable.as_os_str() != expected.as_os_str() {
            return Err(DomainError::UnsafeManagedPath(stable.clone()));
        }
    }

    if let Some(ref cli) = app.cli_symlink_path {
        let expected = layout.bin_dir.join(app.slug.as_str());
        if cli.as_os_str() != expected.as_os_str() {
            return Err(DomainError::UnsafeManagedPath(cli.clone()));
        }
    }

    let expected_desktop = layout
        .desktop_entries_dir
        .join(format!("{}.desktop", app.slug.as_str()));
    if app.desktop_file_path.as_os_str() != expected_desktop.as_os_str() {
        return Err(DomainError::UnsafeManagedPath(
            app.desktop_file_path.clone(),
        ));
    }

    let mut seen_icon_paths: HashSet<&Path> = HashSet::with_capacity(app.icon_paths.len());
    for icon_path in &app.icon_paths {
        validate_icon_path_for_slug(icon_path, &layout.icons_hicolor_dir, app.slug.as_str())?;
        if !seen_icon_paths.insert(icon_path.as_path()) {
            return Err(DomainError::UnsafeManagedPath(icon_path.clone()));
        }
    }

    if let Some(ref desktop_sha) = app.desktop_file_sha256 {
        validate_sha256_hex(desktop_sha)?;
    }

    normalize_and_validate_icon_sha256s(
        &app.icon_paths,
        &app.icon_sha256s,
        &layout.icons_hicolor_dir,
        app.slug.as_str(),
    )?;

    Ok(())
}

pub fn normalize_and_validate_icon_sha256s(
    icon_paths: &[PathBuf],
    icon_sha256s: &BTreeMap<String, String>,
    icons_hicolor_dir: &Path,
    slug: &str,
) -> Result<BTreeMap<String, String>, DomainError> {
    let mut normalized = BTreeMap::new();
    let mut seen_normalized: HashSet<&Path> = HashSet::with_capacity(icon_sha256s.len());
    for (icon_key, icon_sha) in icon_sha256s {
        let icon_key_path = Path::new(icon_key);
        validate_icon_path_for_slug(icon_key_path, icons_hicolor_dir, slug)?;
        if !seen_normalized.insert(icon_key_path) {
            return Err(DomainError::UnsafeManagedPath(icon_key_path.to_path_buf()));
        }
        if !icon_paths
            .iter()
            .any(|p| p.to_str() == Some(icon_key.as_str()))
        {
            return Err(DomainError::UnsafeManagedPath(icon_key_path.to_path_buf()));
        }
        let clean_hex = validate_sha256_hex(icon_sha)?;
        normalized.insert(icon_key.clone(), clean_hex);
    }
    Ok(normalized)
}

pub fn validate_icon_path_for_slug(
    icon_path: &Path,
    icons_hicolor_dir: &Path,
    slug: &str,
) -> Result<(), DomainError> {
    let Ok(rel) = icon_path.strip_prefix(icons_hicolor_dir) else {
        return Err(DomainError::UnsafeManagedPath(icon_path.to_path_buf()));
    };
    let Some(parts) = rel
        .iter()
        .map(|p| p.to_str())
        .collect::<Option<Vec<&str>>>()
    else {
        return Err(DomainError::UnsafeManagedPath(icon_path.to_path_buf()));
    };
    if parts.len() != 3 || parts[1] != "apps" {
        return Err(DomainError::UnsafeManagedPath(icon_path.to_path_buf()));
    }
    let size_dir = parts[0];
    let filename = parts[2];

    if size_dir == "scalable" {
        if filename != format!("{slug}.svg") {
            return Err(DomainError::UnsafeManagedPath(icon_path.to_path_buf()));
        }
    } else {
        let valid_bucket = size_dir
            .split_once('x')
            .and_then(|(w, h)| {
                if w == h {
                    w.parse::<u32>()
                        .ok()
                        .filter(|d| STANDARD_ICON_BUCKETS.contains(d))
                } else {
                    None
                }
            })
            .is_some();

        if !valid_bucket || filename != format!("{slug}.png") {
            return Err(DomainError::UnsafeManagedPath(icon_path.to_path_buf()));
        }
    }

    let expected = icons_hicolor_dir.join(format!("{size_dir}/apps/{filename}"));
    if icon_path.as_os_str() != expected.as_os_str() {
        return Err(DomainError::UnsafeManagedPath(icon_path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::domain::models::{InstalledApp, XdgLayout};
    use crate::domain::slug::AppSlug;

    use super::{
        is_strictly_inside_any, normalize_archive_entry_path, resolve_contained_symlink,
        sanitize_appimage_filename, validate_installed_app_against_layout,
    };

    #[test]
    fn rejects_traversal_and_invalid_archive_paths() {
        assert!(normalize_archive_entry_path("").is_err());
        assert!(normalize_archive_entry_path("../etc/passwd").is_err());
        assert!(normalize_archive_entry_path("usr/../../etc/shadow").is_err());
        assert!(normalize_archive_entry_path("a\\b").is_err());
        assert!(normalize_archive_entry_path("a\0b").is_err());
        assert!(normalize_archive_entry_path("a\u{202E}b").is_err());
        assert!(normalize_archive_entry_path("C:foo").is_err());
        assert!(normalize_archive_entry_path("/").is_err());
    }

    #[test]
    fn normalizes_safe_archive_paths() {
        assert_eq!(
            normalize_archive_entry_path("/./usr/share/icons/app.png")
                .unwrap()
                .to_str()
                .unwrap(),
            "usr/share/icons/app.png"
        );
        assert_eq!(
            normalize_archive_entry_path("usr/share/man/man3/Foo::Bar.3pm")
                .unwrap()
                .to_str()
                .unwrap(),
            "usr/share/man/man3/Foo::Bar.3pm"
        );
        assert_eq!(
            normalize_archive_entry_path(".DirIcon")
                .unwrap()
                .to_str()
                .unwrap(),
            ".DirIcon"
        );
    }

    #[test]
    fn symlink_containment_blocks_escape_and_resolves_inside() {
        assert!(resolve_contained_symlink(Path::new(".DirIcon"), "../../etc/passwd").is_err());
        assert!(resolve_contained_symlink(Path::new("usr/icon.png"), "../../outside").is_err());
        assert!(resolve_contained_symlink(Path::new("usr/icon.png"), "/").is_err());

        let inside_rel = resolve_contained_symlink(
            Path::new(".DirIcon"),
            "usr/share/icons/hicolor/256x256/apps/app.png",
        )
        .unwrap();
        assert_eq!(
            inside_rel,
            Path::new("usr/share/icons/hicolor/256x256/apps/app.png")
        );

        let inside_abs =
            resolve_contained_symlink(Path::new("usr/share/app.png"), "../icons/app.png").unwrap();
        assert_eq!(inside_abs, Path::new("usr/icons/app.png"));
    }

    #[test]
    fn validates_filenames_and_directory_containment() {
        assert!(sanitize_appimage_filename("../evil.AppImage").is_err());
        assert!(sanitize_appimage_filename("-rf.AppImage").is_err());
        assert!(sanitize_appimage_filename(".hidden.AppImage").is_err());
        assert_eq!(
            sanitize_appimage_filename("Obsidian-1.7.4.AppImage").unwrap(),
            "Obsidian-1.7.4.AppImage"
        );
        assert_eq!(
            sanitize_appimage_filename("mytool").unwrap(),
            "mytool.AppImage"
        );

        let root = Path::new("/home/user/Applications");
        assert!(is_strictly_inside_any(
            Path::new("/home/user/Applications/app.AppImage"),
            &[root]
        ));
        assert!(!is_strictly_inside_any(root, &[root]));
        assert!(!is_strictly_inside_any(
            Path::new("/home/user/Applications/../.ssh/id_rsa"),
            &[root]
        ));
    }

    #[test]
    fn validates_installed_app_strict_xdg_shape() {
        let layout = XdgLayout::try_from_env_values(Path::new("/home/user"), None).unwrap();
        let slug = AppSlug::parse_strict("demo").unwrap();
        let valid = InstalledApp {
            slug: slug.clone(),
            name: "Demo".to_string(),
            version: None,
            appimage_path: layout.applications_dir.join("Demo-1.0.AppImage"),
            stable_symlink_path: Some(layout.applications_dir.join("demo.AppImage")),
            cli_symlink_path: Some(layout.bin_dir.join("demo")),
            desktop_file_path: layout.desktop_entries_dir.join("demo.desktop"),
            icon_paths: vec![layout.icons_hicolor_dir.join("256x256/apps/demo.png")],
            sha256: "abc".to_string(),
            desktop_file_sha256: None,
            icon_sha256s: std::collections::BTreeMap::new(),
            installed_at: "2026-11-21T10:00:00Z".to_string(),
        };
        assert!(validate_installed_app_against_layout(&valid, &layout).is_ok());

        let mut bad_icon = valid.clone();
        bad_icon.icon_paths = vec![layout.desktop_entries_dir.join("mimeapps.list")];
        assert!(validate_installed_app_against_layout(&bad_icon, &layout).is_err());

        let mut bad_cli = valid.clone();
        bad_cli.cli_symlink_path = Some(layout.bin_dir.join("other-tool"));
        assert!(validate_installed_app_against_layout(&bad_cli, &layout).is_err());

        let mut bad_bin_subdir = valid.clone();
        bad_bin_subdir.appimage_path = PathBuf::from("/home/user/Applications/sub/Demo.AppImage");
        assert!(validate_installed_app_against_layout(&bad_bin_subdir, &layout).is_err());

        let non_utf8_seg = {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            OsStr::from_bytes(b"256x256-\xff")
        };
        let mut non_utf8_icon = valid.clone();
        non_utf8_icon.icon_paths = vec![
            layout
                .icons_hicolor_dir
                .join(non_utf8_seg)
                .join("256x256/apps/demo.png"),
        ];
        assert!(validate_installed_app_against_layout(&non_utf8_icon, &layout).is_err());

        for non_canonical in [
            "/home/user/.local/share/icons/hicolor/256x256/apps/./demo.png",
            "/home/user/.local/share/icons/hicolor/256x256//apps/demo.png",
            "/home/user/.local/share/icons/hicolor/256x256/apps/demo.png/",
        ] {
            let mut bad_icon_path = valid.clone();
            bad_icon_path.icon_paths = vec![PathBuf::from(non_canonical)];
            assert!(validate_installed_app_against_layout(&bad_icon_path, &layout).is_err());

            let mut bad_icon_key = valid.clone();
            bad_icon_key
                .icon_sha256s
                .insert(non_canonical.to_string(), "a".repeat(64));
            assert!(validate_installed_app_against_layout(&bad_icon_key, &layout).is_err());
        }

        let mut dup_key_app = valid.clone();
        dup_key_app.icon_sha256s.insert(
            "/home/user/.local/share/icons/hicolor/256x256/apps/demo.png".to_string(),
            "a".repeat(64),
        );
        dup_key_app.icon_sha256s.insert(
            "/home/user/.local/share/icons/hicolor/256x256/apps/./demo.png".to_string(),
            "b".repeat(64),
        );
        assert!(validate_installed_app_against_layout(&dup_key_app, &layout).is_err());

        let mut bad_appimage = valid.clone();
        bad_appimage.appimage_path = PathBuf::from("/home/user/Applications/./Demo-1.0.AppImage");
        assert!(validate_installed_app_against_layout(&bad_appimage, &layout).is_err());

        let mut trailing_appimage = valid.clone();
        trailing_appimage.appimage_path =
            PathBuf::from("/home/user/Applications/Demo-1.0.AppImage/");
        assert!(validate_installed_app_against_layout(&trailing_appimage, &layout).is_err());

        let mut bad_desktop = valid.clone();
        bad_desktop.desktop_file_path =
            PathBuf::from("/home/user/.local/share/applications/demo.desktop/");
        assert!(validate_installed_app_against_layout(&bad_desktop, &layout).is_err());

        let mut bad_stable = valid.clone();
        bad_stable.stable_symlink_path =
            Some(PathBuf::from("/home/user/Applications//demo.AppImage"));
        assert!(validate_installed_app_against_layout(&bad_stable, &layout).is_err());

        let mut bad_cli_link = valid;
        bad_cli_link.cli_symlink_path = Some(PathBuf::from("/home/user/.local/bin/./demo"));
        assert!(validate_installed_app_against_layout(&bad_cli_link, &layout).is_err());
    }
}

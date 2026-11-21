#![no_main]

use std::path::Path;

use install_appimage::domain::desktop_entry::{
    normalize_desktop_categories, parse_desktop_entry, render_desktop_entry,
};
use install_appimage::domain::models::ExtractedMetadata;
use install_appimage::domain::path_safety::{
    normalize_archive_entry_path, resolve_contained_symlink,
};
use install_appimage::domain::sanitizer::{
    escape_desktop_exec_path, sanitize_for_error, sanitize_single_line_value,
    sanitize_terminal_text,
};
use install_appimage::domain::slug::AppSlug;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(parsed) = parse_desktop_entry(text) {
        let categories = normalize_desktop_categories(&parsed.categories);
        let meta = ExtractedMetadata {
            app_name: parsed.app_name.unwrap_or_else(|| "FuzzApp".to_string()),
            version: parsed.appimage_version,
            generic_name: parsed.generic_name,
            comment: parsed.comment,
            icon_key: parsed.icon,
            categories,
            mime_types: parsed.mime_types,
            keywords: parsed.keywords,
            startup_wm_class: parsed.startup_wm_class,
            terminal: parsed.terminal,
            startup_notify: parsed.startup_notify,
            exec_field_code: parsed.exec_field_code,
            icons: Vec::new(),
        };
        let _ = render_desktop_entry(
            &meta,
            Path::new("/home/user/Applications/fuzz.AppImage"),
            "fuzz",
        );
    }

    let _ = sanitize_single_line_value(text);
    let _ = sanitize_terminal_text(text);
    let _ = sanitize_for_error(text);
    let _ = escape_desktop_exec_path(text);
    let _ = AppSlug::from_name_or_filename(text);
    let _ = normalize_archive_entry_path(text);
    let _ = resolve_contained_symlink(Path::new("usr/share/icon.png"), text);
});

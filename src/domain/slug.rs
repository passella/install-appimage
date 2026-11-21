use std::fmt;

use crate::domain::error::DomainError;
use crate::domain::sanitizer::sanitize_single_line_value;

const MAX_SLUG_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AppSlug(String);

impl AppSlug {
    pub fn parse_strict(raw: &str) -> Result<Self, DomainError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_SLUG_LEN {
            return Err(DomainError::InvalidSlug(raw.to_string()));
        }
        if trimmed.starts_with('-') || trimmed.ends_with('-') || trimmed.contains("--") {
            return Err(DomainError::InvalidSlug(raw.to_string()));
        }
        if !trimmed
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(DomainError::InvalidSlug(raw.to_string()));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn from_name_or_filename(raw: &str) -> Result<Self, DomainError> {
        let cleaned = sanitize_single_line_value(raw);
        let without_ext = strip_appimage_suffix(&cleaned);
        let mut slug = String::with_capacity(without_ext.len().min(MAX_SLUG_LEN));
        let mut last_dash = true;

        for ch in without_ext.chars() {
            if ch.is_ascii_alphanumeric() {
                if slug.len() >= MAX_SLUG_LEN {
                    break;
                }
                slug.push(ch.to_ascii_lowercase());
                last_dash = false;
            } else if !last_dash && !slug.is_empty() {
                if slug.len() >= MAX_SLUG_LEN {
                    break;
                }
                slug.push('-');
                last_dash = true;
            }
        }

        while slug.ends_with('-') {
            slug.pop();
        }

        if slug.is_empty() {
            return Err(DomainError::InvalidSlug(raw.to_string()));
        }

        Self::parse_strict(&slug)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AppSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn strip_appimage_suffix(raw: &str) -> &str {
    let lower = raw.to_ascii_lowercase();
    if lower.ends_with(".appimage") && raw.len() > ".appimage".len() {
        &raw[..raw.len() - ".appimage".len()]
    } else {
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::{AppSlug, strip_appimage_suffix};

    #[test]
    fn rejects_empty_and_punctuation_only_names() {
        assert!(AppSlug::from_name_or_filename("").is_err());
        assert!(AppSlug::from_name_or_filename("   ").is_err());
        assert!(AppSlug::from_name_or_filename("---...///").is_err());
        assert!(AppSlug::parse_strict("").is_err());
        assert!(AppSlug::parse_strict("-bad").is_err());
        assert!(AppSlug::parse_strict("bad-").is_err());
        assert!(AppSlug::parse_strict("a--b").is_err());
        assert!(AppSlug::parse_strict("Bad").is_err());
        assert!(AppSlug::parse_strict("a/b").is_err());
    }

    #[test]
    fn normalizes_names_and_filenames_with_length_limit() {
        assert_eq!(
            AppSlug::from_name_or_filename("Obsidian").unwrap().as_str(),
            "obsidian"
        );
        assert_eq!(
            AppSlug::from_name_or_filename("My Cool App 2.0")
                .unwrap()
                .as_str(),
            "my-cool-app-2-0"
        );
        assert_eq!(
            AppSlug::from_name_or_filename("Obsidian-1.7.4.AppImage")
                .unwrap()
                .as_str(),
            "obsidian-1-7-4"
        );
        assert_eq!(strip_appimage_suffix("Demo.appimage"), "Demo");

        let overlong = "a".repeat(80);
        let slug = AppSlug::from_name_or_filename(&overlong).unwrap();
        assert_eq!(slug.as_str().len(), 64);
    }
}

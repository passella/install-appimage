use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::adapters::outbound::appimage_extractor::resolve_trusted_executable;
use crate::domain::models::{CacheRefreshOutcome, XdgLayout};
use crate::domain::ports::DesktopCachePort;
use crate::domain::sanitizer::sanitize_single_line_value;

#[derive(Default)]
pub struct HostDesktopCacheAdapter;

impl DesktopCachePort for HostDesktopCacheAdapter {
    fn validate_desktop_file(&self, desktop_path: &Path) -> Vec<String> {
        let Some(exe) = resolve_trusted_executable("desktop-file-validate") else {
            return Vec::new();
        };
        let Ok(output) = Command::new(exe)
            .arg("--")
            .arg(desktop_path)
            .stdin(Stdio::null())
            .output()
        else {
            return vec!["failed to execute desktop-file-validate".to_string()];
        };
        if output.status.success() {
            return Vec::new();
        }
        let combined = format!(
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let clean = sanitize_single_line_value(&combined);
        if clean.is_empty() {
            vec![format!(
                "desktop-file-validate reported issues for '{}'",
                desktop_path.display()
            )]
        } else {
            vec![format!("desktop-file-validate: {clean}")]
        }
    }

    fn refresh_desktop_caches(
        &self,
        layout: &XdgLayout,
        dry_run: bool,
    ) -> Vec<CacheRefreshOutcome> {
        let mut outcomes = Vec::with_capacity(3);

        outcomes.push(run_optional_cache_tool(
            "update-desktop-database",
            &[OsStr::new("--"), layout.desktop_entries_dir.as_os_str()],
            dry_run,
        ));

        outcomes.push(run_optional_cache_tool(
            "gtk-update-icon-cache",
            &[
                OsStr::new("-f"),
                OsStr::new("-t"),
                OsStr::new("-q"),
                OsStr::new("--"),
                layout.icons_hicolor_dir.as_os_str(),
            ],
            dry_run,
        ));

        if resolve_trusted_executable("kbuildsycoca6").is_some() {
            outcomes.push(run_optional_cache_tool(
                "kbuildsycoca6",
                &[OsStr::new("--noincremental")],
                dry_run,
            ));
        } else if resolve_trusted_executable("kbuildsycoca5").is_some() {
            outcomes.push(run_optional_cache_tool(
                "kbuildsycoca5",
                &[OsStr::new("--noincremental")],
                dry_run,
            ));
        } else {
            outcomes.push(CacheRefreshOutcome {
                tool: "kbuildsycoca6".to_string(),
                executed: false,
                detail: "skipped (not installed)".to_string(),
            });
        }

        outcomes
    }
}

fn run_optional_cache_tool(tool_name: &str, args: &[&OsStr], dry_run: bool) -> CacheRefreshOutcome {
    let Some(exe) = resolve_trusted_executable(tool_name) else {
        return CacheRefreshOutcome {
            tool: tool_name.to_string(),
            executed: false,
            detail: "skipped (not installed)".to_string(),
        };
    };

    if dry_run {
        return CacheRefreshOutcome {
            tool: tool_name.to_string(),
            executed: false,
            detail: format!("would run {}", exe.display()),
        };
    }

    match Command::new(exe).args(args).stdin(Stdio::null()).output() {
        Ok(output) if output.status.success() => CacheRefreshOutcome {
            tool: tool_name.to_string(),
            executed: true,
            detail: "updated".to_string(),
        },
        Ok(output) => {
            let reason = sanitize_single_line_value(&String::from_utf8_lossy(&output.stderr));
            CacheRefreshOutcome {
                tool: tool_name.to_string(),
                executed: true,
                detail: if reason.is_empty() {
                    format!("exited with status {}", output.status)
                } else {
                    format!("warning: {reason}")
                },
            }
        }
        Err(err) => CacheRefreshOutcome {
            tool: tool_name.to_string(),
            executed: false,
            detail: format!("warning: failed to spawn ({err})"),
        },
    }
}

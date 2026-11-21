use std::collections::BTreeSet;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::process::geteuid;

use crate::adapters::outbound::appimage_extractor::resolve_trusted_executable;
use crate::domain::models::{DoctorCheck, DoctorCheckStatus, DoctorReport, XdgLayout};
use crate::domain::ports::{ClockPort, SystemProbePort};
use crate::domain::time::format_unix_timestamp_utc;

#[derive(Default)]
pub struct SystemClock;

impl ClockPort for SystemClock {
    fn utc_timestamp_iso8601(&self) -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format_unix_timestamp_utc(secs)
    }
}

#[derive(Debug, Clone)]
pub struct HostObservation {
    pub running_as_root: bool,
    pub has_libfuse2: bool,
    pub has_libfuse3: bool,
    pub fusermount_path: Option<PathBuf>,
    pub fusermount3_path: Option<PathBuf>,
    pub desktop_file_validate_path: Option<PathBuf>,
    pub update_desktop_database_path: Option<PathBuf>,
    pub gtk_update_icon_cache_path: Option<PathBuf>,
    pub kbuildsycoca6_path: Option<PathBuf>,
    pub kbuildsycoca5_path: Option<PathBuf>,
    pub bin_dir_in_path: bool,
    pub dir_states: Vec<DirectoryProbeState>,
}

#[derive(Debug, Clone)]
pub struct DirectoryProbeState {
    pub label: String,
    pub path: PathBuf,
    pub exists: bool,
    pub writable_or_creatable: bool,
}

#[derive(Default)]
pub struct ArchSystemProbeAdapter;

impl SystemProbePort for ArchSystemProbeAdapter {
    fn probe_environment(&self, layout: &XdgLayout) -> DoctorReport {
        let observation = collect_host_observation(layout);
        evaluate_host_observation(&observation)
    }
}

pub fn evaluate_host_observation(obs: &HostObservation) -> DoctorReport {
    let mut checks = Vec::new();
    let mut missing_packages: BTreeSet<String> = BTreeSet::new();

    if obs.running_as_root {
        checks.push(DoctorCheck {
            name: "execution-privilege".to_string(),
            status: DoctorCheckStatus::Warning,
            detail: "running as root; install-appimage is designed for user-level XDG installation without sudo".to_string(),
            pacman_package: None,
            remediation: Some("Run as your regular desktop user without sudo".to_string()),
        });
    } else {
        checks.push(DoctorCheck {
            name: "execution-privilege".to_string(),
            status: DoctorCheckStatus::Ok,
            detail: "running as unprivileged user (user-level XDG mode)".to_string(),
            pacman_package: None,
            remediation: None,
        });
    }

    if obs.has_libfuse2 {
        checks.push(DoctorCheck {
            name: "libfuse2".to_string(),
            status: DoctorCheckStatus::Ok,
            detail: "libfuse.so.2 available (Type 2 legacy AppImage runtime supported)".to_string(),
            pacman_package: None,
            remediation: None,
        });
    } else {
        missing_packages.insert("fuse2".to_string());
        checks.push(DoctorCheck {
            name: "libfuse2".to_string(),
            status: DoctorCheckStatus::Missing,
            detail: "libfuse.so.2 not detected (older AppImages fail to launch without FUSE 2)"
                .to_string(),
            pacman_package: Some("fuse2".to_string()),
            remediation: Some("sudo pacman -S fuse2".to_string()),
        });
    }

    if obs.has_libfuse3 || obs.fusermount3_path.is_some() {
        checks.push(DoctorCheck {
            name: "libfuse3".to_string(),
            status: DoctorCheckStatus::Ok,
            detail: format!(
                "FUSE 3 available ({})",
                obs.fusermount3_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "libfuse3.so.3".to_string())
            ),
            pacman_package: None,
            remediation: None,
        });
    } else {
        missing_packages.insert("fuse3".to_string());
        checks.push(DoctorCheck {
            name: "libfuse3".to_string(),
            status: DoctorCheckStatus::Missing,
            detail: "FUSE 3 / fusermount3 not detected (modern AppImage runtimes need FUSE 3)"
                .to_string(),
            pacman_package: Some("fuse3".to_string()),
            remediation: Some("sudo pacman -S fuse3".to_string()),
        });
    }

    if obs.fusermount_path.is_some() || obs.fusermount3_path.is_some() {
        let found = obs
            .fusermount3_path
            .as_ref()
            .or(obs.fusermount_path.as_ref())
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        checks.push(DoctorCheck {
            name: "fusermount".to_string(),
            status: DoctorCheckStatus::Ok,
            detail: format!("found {found}"),
            pacman_package: None,
            remediation: None,
        });
    } else {
        missing_packages.insert("fuse3".to_string());
        checks.push(DoctorCheck {
            name: "fusermount".to_string(),
            status: DoctorCheckStatus::Missing,
            detail: "neither fusermount nor fusermount3 found in PATH".to_string(),
            pacman_package: Some("fuse3".to_string()),
            remediation: Some("sudo pacman -S fuse3".to_string()),
        });
    }

    check_required_binary(
        &mut checks,
        &mut missing_packages,
        "desktop-file-validate",
        obs.desktop_file_validate_path.as_deref(),
        "desktop-file-utils",
        "validates generated .desktop entries",
    );
    check_required_binary(
        &mut checks,
        &mut missing_packages,
        "update-desktop-database",
        obs.update_desktop_database_path.as_deref(),
        "desktop-file-utils",
        "updates MIME and desktop application cache",
    );
    check_required_binary(
        &mut checks,
        &mut missing_packages,
        "gtk-update-icon-cache",
        obs.gtk_update_icon_cache_path.as_deref(),
        "gtk-update-icon-cache",
        "refreshes hicolor icon theme cache",
    );

    if let Some(ref k6) = obs.kbuildsycoca6_path {
        checks.push(DoctorCheck {
            name: "kbuildsycoca".to_string(),
            status: DoctorCheckStatus::Ok,
            detail: format!("found {}", k6.display()),
            pacman_package: None,
            remediation: None,
        });
    } else if let Some(ref k5) = obs.kbuildsycoca5_path {
        checks.push(DoctorCheck {
            name: "kbuildsycoca".to_string(),
            status: DoctorCheckStatus::Ok,
            detail: format!("found {} (legacy KDE 5)", k5.display()),
            pacman_package: None,
            remediation: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "kbuildsycoca".to_string(),
            status: DoctorCheckStatus::Warning,
            detail: "kbuildsycoca6/kbuildsycoca5 not found (optional; only needed on KDE Plasma)"
                .to_string(),
            pacman_package: Some("kservice".to_string()),
            remediation: Some("Optional on KDE Plasma: sudo pacman -S kservice".to_string()),
        });
    }

    if obs.bin_dir_in_path {
        checks.push(DoctorCheck {
            name: "path-local-bin".to_string(),
            status: DoctorCheckStatus::Ok,
            detail: "~/.local/bin is present in PATH".to_string(),
            pacman_package: None,
            remediation: None,
        });
    } else {
        checks.push(DoctorCheck {
            name: "path-local-bin".to_string(),
            status: DoctorCheckStatus::Warning,
            detail: "~/.local/bin is missing from PATH; CLI symlinks will not resolve by bare name"
                .to_string(),
            pacman_package: None,
            remediation: Some(
                "Add export PATH=\"$HOME/.local/bin:$PATH\" to ~/.bashrc or ~/.zshrc".to_string(),
            ),
        });
    }

    for dir in &obs.dir_states {
        if dir.writable_or_creatable {
            let suffix = if dir.exists {
                "exists, writable"
            } else {
                "creatable"
            };
            checks.push(DoctorCheck {
                name: format!("xdg-dir:{}", dir.label),
                status: DoctorCheckStatus::Ok,
                detail: format!("{} ({suffix})", dir.path.display()),
                pacman_package: None,
                remediation: None,
            });
        } else {
            checks.push(DoctorCheck {
                name: format!("xdg-dir:{}", dir.label),
                status: DoctorCheckStatus::Missing,
                detail: format!("{} is not writable or creatable", dir.path.display()),
                pacman_package: None,
                remediation: Some(format!(
                    "Check ownership and permissions on {}",
                    dir.path.display()
                )),
            });
        }
    }

    let missing_pacman_packages: Vec<String> = missing_packages.into_iter().collect();
    let healthy = checks
        .iter()
        .all(|c| c.status != DoctorCheckStatus::Missing);

    DoctorReport {
        checks,
        missing_pacman_packages,
        healthy,
    }
}

fn check_required_binary(
    checks: &mut Vec<DoctorCheck>,
    missing_packages: &mut BTreeSet<String>,
    name: &str,
    path: Option<&Path>,
    pacman_pkg: &str,
    purpose: &str,
) {
    if let Some(found) = path {
        checks.push(DoctorCheck {
            name: name.to_string(),
            status: DoctorCheckStatus::Ok,
            detail: format!("found {}", found.display()),
            pacman_package: None,
            remediation: None,
        });
    } else {
        missing_packages.insert(pacman_pkg.to_string());
        checks.push(DoctorCheck {
            name: name.to_string(),
            status: DoctorCheckStatus::Missing,
            detail: format!("not found ({purpose})"),
            pacman_package: Some(pacman_pkg.to_string()),
            remediation: Some(format!("sudo pacman -S {pacman_pkg}")),
        });
    }
}

fn collect_host_observation(layout: &XdgLayout) -> HostObservation {
    let running_as_root = geteuid().is_root();
    let has_libfuse2 = has_shared_lib(&["/usr/lib/libfuse.so.2", "/usr/lib64/libfuse.so.2"])
        || pacman_has_package("fuse2");
    let has_libfuse3 = has_shared_lib(&["/usr/lib/libfuse3.so.3", "/usr/lib64/libfuse3.so.3"])
        || pacman_has_package("fuse3");

    let path_var = env::var_os("PATH");
    let bin_dir_in_path = path_var
        .as_ref()
        .map(|pv| {
            env::split_paths(pv).any(|entry| {
                entry == layout.bin_dir
                    || (entry.exists()
                        && layout.bin_dir.exists()
                        && std::fs::canonicalize(&entry).ok()
                            == std::fs::canonicalize(&layout.bin_dir).ok())
            })
        })
        .unwrap_or(false);

    let registry_dir = layout
        .registry_path
        .parent()
        .unwrap_or(&layout.desktop_entries_dir);

    let dir_states = vec![
        probe_dir("applications", &layout.applications_dir),
        probe_dir("bin", &layout.bin_dir),
        probe_dir("desktop-entries", &layout.desktop_entries_dir),
        probe_dir("icons-hicolor", &layout.icons_hicolor_dir),
        probe_dir("registry-data", registry_dir),
    ];

    HostObservation {
        running_as_root,
        has_libfuse2,
        has_libfuse3,
        fusermount_path: resolve_trusted_executable("fusermount"),
        fusermount3_path: resolve_trusted_executable("fusermount3"),
        desktop_file_validate_path: resolve_trusted_executable("desktop-file-validate"),
        update_desktop_database_path: resolve_trusted_executable("update-desktop-database"),
        gtk_update_icon_cache_path: resolve_trusted_executable("gtk-update-icon-cache"),
        kbuildsycoca6_path: resolve_trusted_executable("kbuildsycoca6"),
        kbuildsycoca5_path: resolve_trusted_executable("kbuildsycoca5"),
        bin_dir_in_path,
        dir_states,
    }
}

fn has_shared_lib(candidates: &[&str]) -> bool {
    candidates.iter().any(|p| Path::new(p).exists())
}

fn pacman_has_package(pkg: &str) -> bool {
    let Some(pacman) = resolve_trusted_executable("pacman") else {
        return false;
    };
    Command::new(pacman)
        .args(["-Q", pkg])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn probe_dir(label: &str, path: &Path) -> DirectoryProbeState {
    if path.exists() {
        let writable =
            !path.is_symlink() && path.is_dir() && tempfile::NamedTempFile::new_in(path).is_ok();
        return DirectoryProbeState {
            label: label.to_string(),
            path: path.to_path_buf(),
            exists: true,
            writable_or_creatable: writable,
        };
    }

    let mut ancestor = path.parent();
    let mut creatable = false;
    while let Some(cur) = ancestor {
        if cur.exists() {
            creatable =
                !cur.is_symlink() && cur.is_dir() && tempfile::NamedTempFile::new_in(cur).is_ok();
            break;
        }
        ancestor = cur.parent();
    }

    DirectoryProbeState {
        label: label.to_string(),
        path: path.to_path_buf(),
        exists: false,
        writable_or_creatable: creatable,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::domain::models::DoctorCheckStatus;

    use super::{DirectoryProbeState, HostObservation, evaluate_host_observation};

    #[test]
    fn reports_healthy_when_all_dependencies_and_xdg_dirs_are_present() {
        let obs = HostObservation {
            running_as_root: false,
            has_libfuse2: true,
            has_libfuse3: true,
            fusermount_path: Some(PathBuf::from("/usr/bin/fusermount")),
            fusermount3_path: Some(PathBuf::from("/usr/bin/fusermount3")),
            desktop_file_validate_path: Some(PathBuf::from("/usr/bin/desktop-file-validate")),
            update_desktop_database_path: Some(PathBuf::from("/usr/bin/update-desktop-database")),
            gtk_update_icon_cache_path: Some(PathBuf::from("/usr/bin/gtk-update-icon-cache")),
            kbuildsycoca6_path: Some(PathBuf::from("/usr/bin/kbuildsycoca6")),
            kbuildsycoca5_path: None,
            bin_dir_in_path: true,
            dir_states: vec![DirectoryProbeState {
                label: "applications".to_string(),
                path: PathBuf::from("/home/u/Applications"),
                exists: true,
                writable_or_creatable: true,
            }],
        };

        let report = evaluate_host_observation(&obs);
        assert!(report.healthy);
        assert!(report.missing_pacman_packages.is_empty());
        assert!(
            report
                .checks
                .iter()
                .all(|c| c.status == DoctorCheckStatus::Ok)
        );
    }

    #[test]
    fn flags_missing_pacman_packages_while_keeping_optional_tools_as_warnings() {
        let obs = HostObservation {
            running_as_root: true,
            has_libfuse2: false,
            has_libfuse3: false,
            fusermount_path: None,
            fusermount3_path: None,
            desktop_file_validate_path: None,
            update_desktop_database_path: None,
            gtk_update_icon_cache_path: None,
            kbuildsycoca6_path: None,
            kbuildsycoca5_path: None,
            bin_dir_in_path: false,
            dir_states: vec![DirectoryProbeState {
                label: "applications".to_string(),
                path: PathBuf::from("/root/Applications"),
                exists: false,
                writable_or_creatable: false,
            }],
        };

        let report = evaluate_host_observation(&obs);
        assert!(!report.healthy);
        assert_eq!(
            report.missing_pacman_packages,
            vec![
                "desktop-file-utils",
                "fuse2",
                "fuse3",
                "gtk-update-icon-cache",
            ]
        );
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == "kbuildsycoca" && c.status == DoctorCheckStatus::Warning)
        );
        assert!(!report.checks.iter().any(|c| c.name == "bsdtar"));
    }
}

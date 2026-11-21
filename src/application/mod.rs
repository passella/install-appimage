pub mod doctor;
pub mod install;
pub mod list;
pub mod migrate_registry;
pub mod uninstall;
pub mod verify;

use std::path::Path;

use crate::domain::error::DomainError;
use crate::domain::models::InstalledApp;

pub(crate) fn resolve_installed_app_target(
    apps: &[InstalledApp],
    target: &str,
) -> Result<InstalledApp, DomainError> {
    if let Some(exact_slug) = apps
        .iter()
        .find(|app| app.slug.as_str().eq_ignore_ascii_case(target))
    {
        return Ok(exact_slug.clone());
    }

    let target_path = Path::new(target);
    let mut path_matches: Vec<&InstalledApp> = Vec::new();
    for app in apps {
        let direct_path_match = app.appimage_path == target_path
            || app.stable_symlink_path.as_deref() == Some(target_path)
            || app.cli_symlink_path.as_deref() == Some(target_path)
            || app.desktop_file_path == target_path;
        let filename_match = target_path.file_name().is_some_and(|fname| {
            app.appimage_path.file_name() == Some(fname)
                || app
                    .stable_symlink_path
                    .as_deref()
                    .and_then(|p| p.file_name())
                    == Some(fname)
        });

        if direct_path_match || filename_match {
            path_matches.push(app);
        }
    }

    if path_matches.len() == 1 {
        return Ok(path_matches[0].clone());
    }
    if path_matches.len() > 1 {
        return Err(DomainError::AmbiguousUninstallTarget {
            target: target.to_string(),
            candidates: path_matches
                .into_iter()
                .map(|a| a.slug.to_string())
                .collect(),
        });
    }

    let name_matches: Vec<&InstalledApp> = apps
        .iter()
        .filter(|app| app.name.eq_ignore_ascii_case(target))
        .collect();
    match name_matches.len() {
        0 => Err(DomainError::AppNotInstalled(target.to_string())),
        1 => Ok(name_matches[0].clone()),
        _ => Err(DomainError::AmbiguousUninstallTarget {
            target: target.to_string(),
            candidates: name_matches
                .into_iter()
                .map(|a| a.slug.to_string())
                .collect(),
        }),
    }
}

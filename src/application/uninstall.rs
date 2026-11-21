use crate::application::resolve_installed_app_target;
use crate::domain::error::DomainError;
use crate::domain::models::{UninstallOptions, UninstallSummary, XdgLayout};
use crate::domain::path_safety::{root_for_managed_path, validate_installed_app_against_layout};
use crate::domain::ports::{DesktopCachePort, FileSystemPort, RegistryPort, collect_owned_paths};

pub struct UninstallUseCase<'a> {
    fs: &'a dyn FileSystemPort,
    registry: &'a dyn RegistryPort,
    desktop_cache: &'a dyn DesktopCachePort,
}

impl<'a> UninstallUseCase<'a> {
    pub fn new(
        fs: &'a dyn FileSystemPort,
        registry: &'a dyn RegistryPort,
        desktop_cache: &'a dyn DesktopCachePort,
    ) -> Self {
        Self {
            fs,
            registry,
            desktop_cache,
        }
    }

    pub fn execute(
        &self,
        layout: &XdgLayout,
        options: &UninstallOptions,
    ) -> Result<UninstallSummary, DomainError> {
        let trimmed = options.target.trim();
        if trimmed.is_empty() {
            return Err(DomainError::AppNotInstalled(options.target.clone()));
        }

        let mut apps = self.registry.load(layout)?;
        let target_app = resolve_installed_app_target(&apps, trimmed)?;

        validate_installed_app_against_layout(&target_app, layout)?;
        let managed_roots = layout.managed_roots();
        let owned_paths = collect_owned_paths(&target_app);
        for path in &owned_paths {
            let root = root_for_managed_path(path, &managed_roots)
                .ok_or_else(|| DomainError::UnsafeManagedPath(path.clone()))?;
            self.fs.ensure_symlink_free_path(root, path)?;
        }

        let mut removed_paths = Vec::with_capacity(owned_paths.len());
        let mut warnings = Vec::new();

        for path in owned_paths {
            let root = root_for_managed_path(&path, &managed_roots)
                .ok_or_else(|| DomainError::UnsafeManagedPath(path.clone()))?;
            let removed = if options.dry_run {
                self.fs.path_or_symlink_exists(&path)
            } else {
                self.fs.remove_file_if_exists(root, &path, false)?
            };
            if removed {
                removed_paths.push(path);
            } else {
                warnings.push(format!(
                    "Tracked path already absent on disk: {}",
                    path.display()
                ));
            }
        }

        apps.retain(|app| app.slug != target_app.slug);
        self.registry.save(layout, &apps, options.dry_run)?;

        let cache_outcomes = self
            .desktop_cache
            .refresh_desktop_caches(layout, options.dry_run);

        Ok(UninstallSummary {
            dry_run: options.dry_run,
            removed_app: target_app,
            removed_paths,
            warnings,
            cache_outcomes,
        })
    }
}

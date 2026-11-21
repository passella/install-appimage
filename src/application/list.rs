use crate::domain::error::DomainError;
use crate::domain::models::{ListedApp, XdgLayout};
use crate::domain::ports::{FileSystemPort, RegistryPort};

pub struct ListUseCase<'a> {
    fs: &'a dyn FileSystemPort,
    registry: &'a dyn RegistryPort,
}

impl<'a> ListUseCase<'a> {
    pub fn new(fs: &'a dyn FileSystemPort, registry: &'a dyn RegistryPort) -> Self {
        Self { fs, registry }
    }

    pub fn execute(&self, layout: &XdgLayout) -> Result<Vec<ListedApp>, DomainError> {
        let mut apps = self.registry.load(layout)?;
        apps.sort_by(|a, b| a.slug.cmp(&b.slug));

        let listed = apps
            .into_iter()
            .map(|app| {
                let binary_present = self.fs.is_regular_non_symlink_file(&app.appimage_path);
                let desktop_present = self.fs.is_regular_non_symlink_file(&app.desktop_file_path);
                ListedApp {
                    app,
                    binary_present,
                    desktop_present,
                }
            })
            .collect();

        Ok(listed)
    }
}

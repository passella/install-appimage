use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{Mode, OFlags, open};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::domain::error::DomainError;
use crate::domain::ports::{FileSystemPort, ManagedArtifactProbe, ManagedFileHashProbe};

static TEMP_LINK_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
pub struct XdgFileSystemAdapter;

impl FileSystemPort for XdgFileSystemAdapter {
    fn path_or_symlink_exists(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok()
    }

    fn is_regular_non_symlink_file(&self, path: &Path) -> bool {
        fs::symlink_metadata(path)
            .map(|meta| !meta.file_type().is_symlink() && meta.file_type().is_file())
            .unwrap_or(false)
    }

    fn hash_managed_regular_file(
        &self,
        root: &Path,
        path: &Path,
    ) -> Result<ManagedFileHashProbe, DomainError> {
        match open_managed_regular_file(root, path, "opening managed file")? {
            ManagedOpenResult::File(mut file) => {
                let digest = hash_open_file(&mut file, path)?;
                Ok(ManagedFileHashProbe::Hashed(digest))
            }
            ManagedOpenResult::Missing => Ok(ManagedFileHashProbe::Missing),
            ManagedOpenResult::NotRegularFile(reason) => {
                Ok(ManagedFileHashProbe::NotRegularFile(reason))
            }
            ManagedOpenResult::UnsafePath(reason) => Ok(ManagedFileHashProbe::UnsafePath(reason)),
        }
    }

    fn verify_managed_regular_file(
        &self,
        root: &Path,
        path: &Path,
        expected_sha256: Option<&str>,
    ) -> Result<ManagedArtifactProbe, DomainError> {
        match open_managed_regular_file(root, path, "opening managed artifact")? {
            ManagedOpenResult::File(mut file) => {
                if let Some(expected) = expected_sha256 {
                    let actual = hash_open_file(&mut file, path)?;
                    if actual != expected {
                        return Ok(ManagedArtifactProbe::Invalid(format!(
                            "sha256 checksum mismatch (expected {expected}, got {actual})"
                        )));
                    }
                }
                Ok(ManagedArtifactProbe::Ok)
            }
            ManagedOpenResult::Missing => Ok(ManagedArtifactProbe::Missing),
            ManagedOpenResult::NotRegularFile(reason) => Ok(ManagedArtifactProbe::Invalid(reason)),
            ManagedOpenResult::UnsafePath(reason) => Ok(ManagedArtifactProbe::UnsafePath(reason)),
        }
    }

    fn verify_managed_symlink(
        &self,
        root: &Path,
        link_path: &Path,
        allowed_targets: &[&Path],
    ) -> Result<ManagedArtifactProbe, DomainError> {
        if let Err(DomainError::UnsafeManagedPath(bad)) =
            verify_no_symlink_dirs_under_root(root, link_path, false)
        {
            return Ok(ManagedArtifactProbe::UnsafePath(format!(
                "path '{}' is outside '{}' or traverses a symlink directory",
                bad.display(),
                root.display()
            )));
        }
        if !link_path.starts_with(root) || link_path == root {
            return Ok(ManagedArtifactProbe::UnsafePath(format!(
                "symlink '{}' is outside '{}'",
                link_path.display(),
                root.display()
            )));
        }

        let meta = match fs::symlink_metadata(link_path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Ok(ManagedArtifactProbe::Missing);
            }
            Err(err) => {
                return Err(DomainError::Io {
                    context: format!("statting symlink '{}'", link_path.display()),
                    reason: err.to_string(),
                });
            }
        };
        if !meta.file_type().is_symlink() {
            return Ok(ManagedArtifactProbe::Invalid(
                "expected symbolic link, found non-symlink".to_string(),
            ));
        }

        let raw_target = fs::read_link(link_path).map_err(|err| DomainError::Io {
            context: format!("reading symlink '{}'", link_path.display()),
            reason: err.to_string(),
        })?;

        let Some(resolved) = resolve_symlink_target_under_parent(link_path, &raw_target) else {
            return Ok(ManagedArtifactProbe::Invalid(format!(
                "symlink points to unsafe target '{}'",
                raw_target.display()
            )));
        };

        if !allowed_targets.contains(&resolved.as_path()) {
            return Ok(ManagedArtifactProbe::Invalid(format!(
                "symlink points to unexpected target '{}'",
                raw_target.display()
            )));
        }

        match fs::metadata(link_path) {
            Ok(target_meta) if target_meta.is_file() => Ok(ManagedArtifactProbe::Ok),
            Ok(_) => Ok(ManagedArtifactProbe::Invalid(
                "symlink target is not a regular file".to_string(),
            )),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(ManagedArtifactProbe::Invalid(
                "symlink target is missing (dangling symlink)".to_string(),
            )),
            Err(err) => Err(DomainError::Io {
                context: format!("statting symlink target '{}'", link_path.display()),
                reason: err.to_string(),
            }),
        }
    }

    fn same_file(&self, left: &Path, right: &Path) -> Result<bool, DomainError> {
        let Ok(left_sym) = fs::symlink_metadata(left) else {
            return Ok(false);
        };
        if left_sym.file_type().is_symlink() || !left_sym.file_type().is_file() {
            return Ok(false);
        }
        let Ok(right_sym) = fs::symlink_metadata(right) else {
            return Ok(false);
        };
        if right_sym.file_type().is_symlink() || !right_sym.file_type().is_file() {
            return Ok(false);
        }
        Ok(left_sym.dev() == right_sym.dev() && left_sym.ino() == right_sym.ino())
    }

    fn ensure_symlink_free_path(&self, root: &Path, target: &Path) -> Result<(), DomainError> {
        verify_no_symlink_dirs_under_root(root, target, false)
    }

    fn create_dir_all_safe(
        &self,
        root: &Path,
        path: &Path,
        dry_run: bool,
    ) -> Result<(), DomainError> {
        verify_no_symlink_dirs_under_root(root, path, true)?;
        if dry_run {
            return Ok(());
        }

        if let Ok(meta) = fs::symlink_metadata(root) {
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(DomainError::UnsafeManagedPath(root.to_path_buf()));
            }
        } else {
            fs::create_dir_all(root).map_err(|err| DomainError::Io {
                context: format!("creating root directory '{}'", root.display()),
                reason: err.to_string(),
            })?;
        }

        if path == root {
            return Ok(());
        }

        let rel = path
            .strip_prefix(root)
            .map_err(|_| DomainError::UnsafeManagedPath(path.to_path_buf()))?;
        let mut cursor = root.to_path_buf();
        for comp in rel.components() {
            let Component::Normal(part) = comp else {
                return Err(DomainError::UnsafeManagedPath(path.to_path_buf()));
            };
            cursor.push(part);
            match fs::symlink_metadata(&cursor) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                        return Err(DomainError::UnsafeManagedPath(cursor));
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    fs::create_dir(&cursor)
                        .or_else(|mkdir_err| {
                            if mkdir_err.kind() == io::ErrorKind::AlreadyExists {
                                let meta = fs::symlink_metadata(&cursor)?;
                                if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "symlink encountered while creating directory",
                                    ));
                                }
                                Ok(())
                            } else {
                                Err(mkdir_err)
                            }
                        })
                        .map_err(|err| DomainError::Io {
                            context: format!("creating directory '{}'", cursor.display()),
                            reason: err.to_string(),
                        })?;
                }
                Err(err) => {
                    return Err(DomainError::Io {
                        context: format!("inspecting directory '{}'", cursor.display()),
                        reason: err.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    fn install_executable_verified(
        &self,
        src: &Path,
        dst: &Path,
        expected_sha256: &str,
        move_source: bool,
        dry_run: bool,
    ) -> Result<(), DomainError> {
        let fd = open(
            src,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| {
            if errno == rustix::io::Errno::LOOP {
                DomainError::NotARegularFile(src.to_path_buf())
            } else {
                DomainError::Io {
                    context: format!("opening source AppImage '{}'", src.display()),
                    reason: errno.to_string(),
                }
            }
        })?;
        let mut src_file = File::from(fd);
        let src_meta = src_file.metadata().map_err(|err| DomainError::Io {
            context: format!("statting source AppImage '{}'", src.display()),
            reason: err.to_string(),
        })?;
        if !src_meta.is_file() {
            return Err(DomainError::NotARegularFile(src.to_path_buf()));
        }

        if dry_run {
            return Ok(());
        }

        let parent = dst.parent().ok_or_else(|| DomainError::Io {
            context: format!("resolving parent of '{}'", dst.display()),
            reason: "destination has no parent directory".to_string(),
        })?;
        ensure_dir_not_symlink(parent)?;

        if self.same_file(src, dst)? {
            let actual_sha256 = hash_open_file(&mut src_file, src)?;
            if actual_sha256 != expected_sha256 {
                return Err(DomainError::InvalidAppImage {
                    path: src.to_path_buf(),
                    reason: "AppImage content changed during installation (SHA-256 mismatch)"
                        .to_string(),
                });
            }
            src_file
                .set_permissions(Permissions::from_mode(0o755))
                .map_err(|err| DomainError::Io {
                    context: format!("setting executable permissions on '{}'", dst.display()),
                    reason: err.to_string(),
                })?;
            if move_source && is_distinct_directory_entry(src, dst)? {
                unlink_pinned_source(src, src_meta.dev(), src_meta.ino())?;
            }
            return Ok(());
        }

        let mut tmp = NamedTempFile::new_in(parent).map_err(|err| DomainError::Io {
            context: format!("creating staging file in '{}'", parent.display()),
            reason: err.to_string(),
        })?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = src_file.read(&mut buf).map_err(|err| DomainError::Io {
                context: format!("reading source AppImage '{}'", src.display()),
                reason: err.to_string(),
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            tmp.write_all(&buf[..n]).map_err(|err| DomainError::Io {
                context: format!("writing staged AppImage '{}'", dst.display()),
                reason: err.to_string(),
            })?;
        }
        let staged_sha256 = hex::encode(hasher.finalize());
        if staged_sha256 != expected_sha256 {
            return Err(DomainError::InvalidAppImage {
                path: src.to_path_buf(),
                reason: "AppImage content changed during installation (SHA-256 mismatch)"
                    .to_string(),
            });
        }

        tmp.as_file().sync_all().map_err(|err| DomainError::Io {
            context: format!("syncing staged AppImage '{}'", dst.display()),
            reason: err.to_string(),
        })?;
        tmp.as_file()
            .set_permissions(Permissions::from_mode(0o755))
            .map_err(|err| DomainError::Io {
                context: format!("chmod 755 on '{}'", dst.display()),
                reason: err.to_string(),
            })?;

        tmp.persist(dst).map_err(|err| DomainError::Io {
            context: format!("persisting AppImage '{}'", dst.display()),
            reason: err.error.to_string(),
        })?;

        if move_source {
            unlink_pinned_source(src, src_meta.dev(), src_meta.ino())?;
        }

        Ok(())
    }

    fn write_file_atomic(
        &self,
        root: &Path,
        path: &Path,
        contents: &[u8],
        mode: u32,
        dry_run: bool,
    ) -> Result<(), DomainError> {
        verify_no_symlink_dirs_under_root(root, path, false)?;
        if dry_run {
            return Ok(());
        }
        let parent = path.parent().ok_or_else(|| DomainError::Io {
            context: format!("resolving parent of '{}'", path.display()),
            reason: "path has no parent directory".to_string(),
        })?;
        let mut tmp = NamedTempFile::new_in(parent).map_err(|err| DomainError::Io {
            context: format!("creating temp file in '{}'", parent.display()),
            reason: err.to_string(),
        })?;
        tmp.write_all(contents).map_err(|err| DomainError::Io {
            context: format!("writing '{}'", path.display()),
            reason: err.to_string(),
        })?;
        tmp.as_file().sync_all().map_err(|err| DomainError::Io {
            context: format!("syncing '{}'", path.display()),
            reason: err.to_string(),
        })?;
        tmp.as_file()
            .set_permissions(Permissions::from_mode(mode))
            .map_err(|err| DomainError::Io {
                context: format!("setting permissions on '{}'", path.display()),
                reason: err.to_string(),
            })?;
        tmp.persist(path).map_err(|err| DomainError::Io {
            context: format!("persisting '{}'", path.display()),
            reason: err.error.to_string(),
        })?;
        Ok(())
    }

    fn create_symlink_atomic(
        &self,
        root: &Path,
        target: &Path,
        link_path: &Path,
        dry_run: bool,
    ) -> Result<(), DomainError> {
        verify_no_symlink_dirs_under_root(root, link_path, false)?;
        if dry_run {
            return Ok(());
        }
        let parent = link_path.parent().ok_or_else(|| DomainError::Io {
            context: format!("resolving parent of symlink '{}'", link_path.display()),
            reason: "symlink path has no parent directory".to_string(),
        })?;
        let pid = std::process::id();
        let mut tmp_link: Option<PathBuf> = None;

        for _ in 0..16 {
            let seq = TEMP_LINK_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(".install-appimage-link-{pid}-{seq}"));
            match symlink(target, &candidate) {
                Ok(()) => {
                    tmp_link = Some(candidate);
                    break;
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(DomainError::Io {
                        context: format!("creating staging symlink '{}'", candidate.display()),
                        reason: err.to_string(),
                    });
                }
            }
        }

        let staging_link = tmp_link.ok_or_else(|| DomainError::Io {
            context: format!("allocating temp symlink for '{}'", link_path.display()),
            reason: "exhausted staging symlink retries".to_string(),
        })?;

        if let Err(err) = fs::rename(&staging_link, link_path) {
            let _ = fs::remove_file(&staging_link);
            return Err(DomainError::Io {
                context: format!("renaming symlink to '{}'", link_path.display()),
                reason: err.to_string(),
            });
        }
        Ok(())
    }

    fn remove_file_if_exists(
        &self,
        root: &Path,
        path: &Path,
        dry_run: bool,
    ) -> Result<bool, DomainError> {
        verify_no_symlink_dirs_under_root(root, path, false)?;
        let Ok(meta) = fs::symlink_metadata(path) else {
            return Ok(false);
        };
        if meta.is_dir() {
            return Err(DomainError::Io {
                context: format!("removing '{}'", path.display()),
                reason: "refusing to unlink directory where file or symlink expected".to_string(),
            });
        }
        if dry_run {
            return Ok(true);
        }
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(DomainError::Io {
                context: format!("removing '{}'", path.display()),
                reason: err.to_string(),
            }),
        }
    }
}

pub fn verify_no_symlink_dirs_under_root(
    root: &Path,
    target: &Path,
    include_leaf_as_dir: bool,
) -> Result<(), DomainError> {
    if !root.is_absolute() || root.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(DomainError::UnsafeManagedPath(root.to_path_buf()));
    }
    if let Ok(meta) = fs::symlink_metadata(root)
        && (meta.file_type().is_symlink() || !meta.file_type().is_dir())
    {
        return Err(DomainError::UnsafeManagedPath(root.to_path_buf()));
    }

    if target == root {
        return Ok(());
    }

    let check_path = if include_leaf_as_dir {
        target
    } else {
        target
            .parent()
            .ok_or_else(|| DomainError::UnsafeManagedPath(target.to_path_buf()))?
    };

    if check_path == root {
        return Ok(());
    }

    let rel = check_path
        .strip_prefix(root)
        .map_err(|_| DomainError::UnsafeManagedPath(target.to_path_buf()))?;
    let mut cursor = root.to_path_buf();
    for comp in rel.components() {
        let Component::Normal(part) = comp else {
            return Err(DomainError::UnsafeManagedPath(target.to_path_buf()));
        };
        cursor.push(part);
        if let Ok(meta) = fs::symlink_metadata(&cursor)
            && (meta.file_type().is_symlink() || !meta.file_type().is_dir())
        {
            return Err(DomainError::UnsafeManagedPath(cursor));
        }
    }
    Ok(())
}

fn ensure_dir_not_symlink(dir: &Path) -> Result<(), DomainError> {
    let meta = fs::symlink_metadata(dir).map_err(|err| DomainError::Io {
        context: format!("statting directory '{}'", dir.display()),
        reason: err.to_string(),
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(DomainError::UnsafeManagedPath(dir.to_path_buf()));
    }
    Ok(())
}

enum ManagedOpenResult {
    File(File),
    Missing,
    NotRegularFile(String),
    UnsafePath(String),
}

fn open_managed_regular_file(
    root: &Path,
    path: &Path,
    open_context: &str,
) -> Result<ManagedOpenResult, DomainError> {
    if let Err(DomainError::UnsafeManagedPath(bad)) =
        verify_no_symlink_dirs_under_root(root, path, false)
    {
        return Ok(ManagedOpenResult::UnsafePath(format!(
            "path '{}' is outside '{}' or traverses a symlink directory",
            bad.display(),
            root.display()
        )));
    }
    if !path.starts_with(root) || path == root {
        return Ok(ManagedOpenResult::UnsafePath(format!(
            "path '{}' is outside '{}'",
            path.display(),
            root.display()
        )));
    }

    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(ManagedOpenResult::Missing),
        Err(rustix::io::Errno::LOOP) => {
            return Ok(ManagedOpenResult::NotRegularFile(
                "path is a symbolic link".to_string(),
            ));
        }
        Err(errno) => {
            return Err(DomainError::Io {
                context: format!("{open_context} '{}'", path.display()),
                reason: errno.to_string(),
            });
        }
    };

    let file = File::from(fd);
    let meta = file.metadata().map_err(|err| DomainError::Io {
        context: format!("statting managed file '{}'", path.display()),
        reason: err.to_string(),
    })?;
    if !meta.is_file() {
        return Ok(ManagedOpenResult::NotRegularFile(
            "path is not a regular file".to_string(),
        ));
    }

    Ok(ManagedOpenResult::File(file))
}

fn resolve_symlink_target_under_parent(link_path: &Path, raw_target: &Path) -> Option<PathBuf> {
    if raw_target.as_os_str().is_empty() {
        return None;
    }
    if raw_target.is_absolute() {
        if raw_target
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return None;
        }
        return Some(raw_target.to_path_buf());
    }
    let parent = link_path.parent()?;
    let mut resolved = parent.to_path_buf();
    for comp in raw_target.components() {
        match comp {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(resolved)
}

fn hash_open_file(file: &mut File, path: &Path) -> Result<String, DomainError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|err| DomainError::Io {
            context: format!("verifying '{}'", path.display()),
            reason: err.to_string(),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn is_distinct_directory_entry(src: &Path, dst: &Path) -> Result<bool, DomainError> {
    let src_parent = match src.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let dst_parent = match dst.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let src_parent_meta = fs::metadata(src_parent).map_err(|err| DomainError::Io {
        context: format!("statting source parent '{}'", src_parent.display()),
        reason: err.to_string(),
    })?;
    let dst_parent_meta = fs::symlink_metadata(dst_parent).map_err(|err| DomainError::Io {
        context: format!("statting destination parent '{}'", dst_parent.display()),
        reason: err.to_string(),
    })?;
    if !src_parent_meta.is_dir()
        || dst_parent_meta.file_type().is_symlink()
        || !dst_parent_meta.is_dir()
    {
        return Err(DomainError::UnsafeManagedPath(dst.to_path_buf()));
    }
    let same_dir = src_parent_meta.dev() == dst_parent_meta.dev()
        && src_parent_meta.ino() == dst_parent_meta.ino();
    Ok(!(same_dir && src.file_name() == dst.file_name()))
}

fn unlink_pinned_source(
    src: &Path,
    expected_dev: u64,
    expected_ino: u64,
) -> Result<(), DomainError> {
    let cur_meta = fs::symlink_metadata(src).map_err(|err| DomainError::Io {
        context: format!("verifying source '{}' before unlink", src.display()),
        reason: err.to_string(),
    })?;
    if cur_meta.file_type().is_symlink()
        || !cur_meta.file_type().is_file()
        || cur_meta.dev() != expected_dev
        || cur_meta.ino() != expected_ino
    {
        return Err(DomainError::NotARegularFile(src.to_path_buf()));
    }
    fs::remove_file(src).map_err(|err| DomainError::Io {
        context: format!("removing source file '{}' after move", src.display()),
        reason: err.to_string(),
    })
}

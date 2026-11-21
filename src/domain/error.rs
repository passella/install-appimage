use std::path::PathBuf;
use thiserror::Error;

use crate::domain::sanitizer::sanitize_for_error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("input file not found: {0}")]
    InputFileNotFound(PathBuf),

    #[error("input path is not a regular file: {0}")]
    NotARegularFile(PathBuf),

    #[error("invalid AppImage '{path}': {reason}")]
    InvalidAppImage { path: PathBuf, reason: String },

    #[error("unsupported AppImage format for '{path}': {reason}")]
    UnsupportedAppImageFormat { path: PathBuf, reason: String },

    #[error("unsafe path traversal detected in archive entry: '{0}'")]
    UnsafePathTraversal(String),

    #[error("symlink escape detected in archive: '{link}' -> '{target}'")]
    SymlinkEscape { link: String, target: String },

    #[error("resource limit exceeded for {resource} (limit {limit}) during {context}")]
    ResourceLimitExceeded {
        resource: String,
        limit: u64,
        context: String,
    },

    #[error("invalid application slug or name: '{0}'")]
    InvalidSlug(String),

    #[error("invalid desktop entry metadata: {0}")]
    InvalidDesktopEntry(String),

    #[error("target path already exists and is not managed by this app: {path} ({reason})")]
    CollisionDetected { path: PathBuf, reason: String },

    #[error("installed AppImage not found for target '{0}'")]
    AppNotInstalled(String),

    #[error("ambiguous uninstall target '{target}' matches multiple installed apps: {}", .candidates.join(", "))]
    AmbiguousUninstallTarget {
        target: String,
        candidates: Vec<String>,
    },

    #[error("registry file '{path}' is corrupted: {reason}")]
    RegistryCorrupted { path: PathBuf, reason: String },

    #[error("external command '{command}' failed: executable '{executable}' not found")]
    ExecutableNotFound { command: String, executable: String },

    #[error("external command '{command}' failed: {reason}")]
    CommandExecutionFailed { command: String, reason: String },

    #[error("unsafe path outside managed XDG directories: {0}")]
    UnsafeManagedPath(PathBuf),

    #[error("invalid XDG/HOME configuration: {0}")]
    InvalidEnvironmentLayout(String),

    #[error("invalid SHA-256 digest '{0}' (expected 64 hexadecimal characters)")]
    InvalidSha256(String),

    #[error("SHA-256 checksum mismatch for '{path}': expected {expected}, got {actual}")]
    Sha256Mismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("integrity verification failed for {failed} of {total} installed AppImage(s)")]
    IntegrityVerificationFailed { failed: usize, total: usize },

    #[error("registry migration failed for {failed} of {total} installed AppImage(s)")]
    RegistryMigrationFailed { failed: usize, total: usize },

    #[error("I/O error during {context}: {reason}")]
    Io { context: String, reason: String },
}

fn sanitize_path_buf(path: PathBuf) -> PathBuf {
    PathBuf::from(sanitize_for_error(&path.to_string_lossy()))
}

impl DomainError {
    pub fn sanitized(self) -> Self {
        match self {
            Self::InputFileNotFound(path) => Self::InputFileNotFound(sanitize_path_buf(path)),
            Self::NotARegularFile(path) => Self::NotARegularFile(sanitize_path_buf(path)),
            Self::InvalidAppImage { path, reason } => Self::InvalidAppImage {
                path: sanitize_path_buf(path),
                reason: sanitize_for_error(&reason),
            },
            Self::UnsupportedAppImageFormat { path, reason } => Self::UnsupportedAppImageFormat {
                path: sanitize_path_buf(path),
                reason: sanitize_for_error(&reason),
            },
            Self::UnsafePathTraversal(raw) => Self::UnsafePathTraversal(sanitize_for_error(&raw)),
            Self::SymlinkEscape { link, target } => Self::SymlinkEscape {
                link: sanitize_for_error(&link),
                target: sanitize_for_error(&target),
            },
            Self::ResourceLimitExceeded {
                resource,
                limit,
                context,
            } => Self::ResourceLimitExceeded {
                resource: sanitize_for_error(&resource),
                limit,
                context: sanitize_for_error(&context),
            },
            Self::InvalidSlug(raw) => Self::InvalidSlug(sanitize_for_error(&raw)),
            Self::InvalidDesktopEntry(msg) => Self::InvalidDesktopEntry(sanitize_for_error(&msg)),
            Self::CollisionDetected { path, reason } => Self::CollisionDetected {
                path: sanitize_path_buf(path),
                reason: sanitize_for_error(&reason),
            },
            Self::AppNotInstalled(target) => Self::AppNotInstalled(sanitize_for_error(&target)),
            Self::AmbiguousUninstallTarget { target, candidates } => {
                Self::AmbiguousUninstallTarget {
                    target: sanitize_for_error(&target),
                    candidates: candidates
                        .into_iter()
                        .map(|c| sanitize_for_error(&c))
                        .collect(),
                }
            }
            Self::RegistryCorrupted { path, reason } => Self::RegistryCorrupted {
                path: sanitize_path_buf(path),
                reason: sanitize_for_error(&reason),
            },
            Self::ExecutableNotFound {
                command,
                executable,
            } => Self::ExecutableNotFound {
                command: sanitize_for_error(&command),
                executable: sanitize_for_error(&executable),
            },
            Self::CommandExecutionFailed { command, reason } => Self::CommandExecutionFailed {
                command: sanitize_for_error(&command),
                reason: sanitize_for_error(&reason),
            },
            Self::UnsafeManagedPath(path) => Self::UnsafeManagedPath(sanitize_path_buf(path)),
            Self::InvalidEnvironmentLayout(msg) => {
                Self::InvalidEnvironmentLayout(sanitize_for_error(&msg))
            }
            Self::InvalidSha256(raw) => Self::InvalidSha256(sanitize_for_error(&raw)),
            Self::Sha256Mismatch {
                path,
                expected,
                actual,
            } => Self::Sha256Mismatch {
                path: sanitize_path_buf(path),
                expected: sanitize_for_error(&expected),
                actual: sanitize_for_error(&actual),
            },
            Self::IntegrityVerificationFailed { failed, total } => {
                Self::IntegrityVerificationFailed { failed, total }
            }
            Self::RegistryMigrationFailed { failed, total } => {
                Self::RegistryMigrationFailed { failed, total }
            }
            Self::Io { context, reason } => Self::Io {
                context: sanitize_for_error(&context),
                reason: sanitize_for_error(&reason),
            },
        }
    }
}

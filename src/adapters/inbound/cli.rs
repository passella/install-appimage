use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{CommandFactory, Parser};
use clap_complete::Shell;
use clap_mangen::Man;
use serde::Serialize;

use crate::application::doctor::DoctorUseCase;
use crate::application::install::InstallUseCase;
use crate::application::list::ListUseCase;
use crate::application::migrate_registry::MigrateRegistryUseCase;
use crate::application::uninstall::UninstallUseCase;
use crate::application::verify::VerifyUseCase;
use crate::domain::error::DomainError;
use crate::domain::models::{
    CacheRefreshOutcome, DoctorCheckStatus, DoctorReport, InstallOptions, InstallSummary,
    InstalledApp, ListedApp, MigrateRegistryEntryStatus, MigrateRegistryOptions,
    MigrateRegistryReport, UninstallOptions, UninstallSummary, VerifyEntryStatus, VerifyOptions,
    VerifyReport, XdgLayout, validate_sha256_hex,
};
use crate::domain::ports::{
    AppImageExtractorPort, ClockPort, DesktopCachePort, FileSystemPort, RegistryPort,
    SystemProbePort,
};
use crate::domain::sanitizer::{sanitize_for_error, sanitize_terminal_text};

#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(
    name = "install-appimage",
    version,
    about = "Install, update, list, verify, diagnose, and cleanly uninstall AppImages on Linux with user-level XDG integration"
)]
pub struct CliArgs {
    #[arg(
        value_name = "APPIMAGE",
        required_unless_present_any = ["list", "doctor", "verify", "migrate_registry", "generate_completion", "generate_man"],
        help = "Path to an AppImage file (or app name, slug, or AppImage path when used with -u/--uninstall or --verify)"
    )]
    pub target: Option<String>,

    #[arg(
        short = 'u',
        long = "uninstall",
        conflicts_with_all = ["list", "doctor", "verify", "migrate_registry", "move_source", "name", "no_cli", "force", "sha256"],
        help = "Uninstall a managed AppImage by name, slug, or file path"
    )]
    pub uninstall: bool,

    #[arg(
        short = 'l',
        long = "list",
        conflicts_with_all = ["target", "uninstall", "doctor", "verify", "migrate_registry", "move_source", "name", "no_cli", "force", "dry_run", "sha256"],
        help = "List AppImages installed and managed by install-appimage"
    )]
    pub list: bool,

    #[arg(
        long = "doctor",
        conflicts_with_all = ["target", "uninstall", "list", "verify", "migrate_registry", "move_source", "name", "no_cli", "force", "dry_run", "sha256"],
        help = "Diagnose Arch Linux / CachyOS runtime dependencies, XDG directories, and PATH setup"
    )]
    pub doctor: bool,

    #[arg(
        long = "verify",
        conflicts_with_all = ["uninstall", "list", "doctor", "migrate_registry", "move_source", "name", "no_cli", "force", "dry_run", "sha256"],
        help = "Verify SHA-256 integrity of installed AppImages against registry.json (optionally pass app name, slug, or path)"
    )]
    pub verify: bool,

    #[arg(
        long = "strict",
        requires = "verify",
        conflicts_with_all = ["uninstall", "list", "doctor", "migrate_registry", "move_source", "name", "no_cli", "force", "dry_run", "sha256"],
        help = "With --verify, also verify .desktop file, stable/CLI symlinks, and icons"
    )]
    pub strict: bool,

    #[arg(
        long = "migrate-registry",
        conflicts_with_all = ["target", "uninstall", "list", "doctor", "verify", "strict", "move_source", "name", "no_cli", "force", "sha256"],
        help = "Migrate registry.json from schema v1 to v2 by hashing existing .desktop and icon artifacts"
    )]
    pub migrate_registry: bool,

    #[arg(
        long = "sha256",
        value_name = "HEX",
        value_parser = parse_sha256_hex,
        conflicts_with_all = ["uninstall", "list", "doctor", "verify"],
        help = "Verify source AppImage SHA-256 checksum (64 hexadecimal digits) before installing"
    )]
    pub sha256: Option<String>,

    #[arg(
        long = "json",
        help = "Emit deterministic structured JSON output on stdout"
    )]
    pub json: bool,

    #[arg(
        long = "generate-completion",
        value_name = "SHELL",
        exclusive = true,
        help = "Print shell completion script for SHELL (bash, zsh, fish, elvish, powershell) to stdout and exit"
    )]
    pub generate_completion: Option<Shell>,

    #[arg(
        long = "generate-man",
        exclusive = true,
        help = "Print roff man page to stdout and exit"
    )]
    pub generate_man: bool,

    #[arg(
        long = "move",
        conflicts_with_all = ["uninstall", "list", "doctor", "verify"],
        help = "Move the AppImage into ~/Applications instead of copying it"
    )]
    pub move_source: bool,

    #[arg(
        long = "name",
        value_name = "NAME",
        conflicts_with_all = ["uninstall", "list", "doctor", "verify"],
        help = "Override the application display name and derived slug"
    )]
    pub name: Option<String>,

    #[arg(
        long = "no-cli",
        conflicts_with_all = ["uninstall", "list", "doctor", "verify"],
        help = "Do not create a CLI symlink in ~/.local/bin"
    )]
    pub no_cli: bool,

    #[arg(
        long = "force",
        conflicts_with_all = ["uninstall", "list", "doctor", "verify"],
        help = "Force overwriting existing unmanaged files or symlinks on collision"
    )]
    pub force: bool,

    #[arg(
        long = "dry-run",
        conflicts_with_all = ["list", "doctor", "verify"],
        help = "Simulate all install or uninstall operations without modifying the filesystem"
    )]
    pub dry_run: bool,
}

pub fn parse_sha256_hex(raw: &str) -> Result<String, String> {
    validate_sha256_hex(raw).map_err(|err| err.to_string())
}

pub fn try_render_static_cli_output(
    args: &CliArgs,
    stdout: &mut dyn Write,
) -> Result<bool, DomainError> {
    if args.json && (args.generate_completion.is_some() || args.generate_man) {
        return Err(DomainError::InvalidAppImage {
            path: PathBuf::new(),
            reason: "--json cannot be combined with --generate-completion or --generate-man"
                .to_string(),
        });
    }

    if let Some(shell) = args.generate_completion {
        let mut cmd = CliArgs::command();
        let mut buf = Vec::new();
        clap_complete::generate(shell, &mut cmd, "install-appimage", &mut buf);
        map_stdout_res(stdout.write_all(&buf))?;
        return Ok(true);
    }

    if args.generate_man {
        let cmd = CliArgs::command();
        let man = Man::new(cmd);
        if let Err(err) = man.render(stdout)
            && err.kind() != std::io::ErrorKind::BrokenPipe
        {
            return Err(DomainError::Io {
                context: "rendering man page".to_string(),
                reason: sanitize_for_error(&err.to_string()),
            });
        }
        return Ok(true);
    }

    Ok(false)
}

#[derive(Serialize)]
struct JsonListResponse {
    apps: Vec<JsonListedAppItem>,
}

#[derive(Serialize)]
struct JsonListedAppItem {
    slug: String,
    name: String,
    version: Option<String>,
    status: &'static str,
    binary_present: bool,
    desktop_present: bool,
    appimage_path: String,
    stable_symlink_path: Option<String>,
    cli_symlink_path: Option<String>,
    desktop_file_path: String,
    icon_paths: Vec<String>,
    sha256: String,
    installed_at: String,
}

#[derive(Serialize)]
struct JsonDoctorResponse {
    healthy: bool,
    missing_pacman_packages: Vec<String>,
    checks: Vec<JsonDoctorCheckItem>,
}

#[derive(Serialize)]
struct JsonDoctorCheckItem {
    name: String,
    status: &'static str,
    detail: String,
    pacman_package: Option<String>,
    remediation: Option<String>,
}

#[derive(Serialize)]
struct JsonVerifyResponse {
    strict: bool,
    all_ok: bool,
    total: usize,
    ok_count: usize,
    failed_count: usize,
    results: Vec<JsonVerifiedAppItem>,
}

#[derive(Serialize)]
struct JsonVerifyArtifactItem {
    kind: &'static str,
    path: String,
    ok: bool,
    detail: String,
}

#[derive(Serialize)]
struct JsonVerifiedAppItem {
    slug: String,
    name: String,
    version: Option<String>,
    appimage_path: String,
    status: &'static str,
    ok: bool,
    expected_sha256: String,
    actual_sha256: Option<String>,
    detail: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    artifacts: Vec<JsonVerifyArtifactItem>,
}

#[derive(Serialize)]
struct JsonInstalledAppInfo {
    slug: String,
    name: String,
    version: Option<String>,
    appimage_path: String,
    stable_symlink_path: Option<String>,
    cli_symlink_path: Option<String>,
    desktop_file_path: String,
    icon_paths: Vec<String>,
    sha256: String,
    installed_at: String,
}

#[derive(Serialize)]
struct JsonCacheOutcomeItem {
    tool: String,
    executed: bool,
    detail: String,
}

#[derive(Serialize)]
struct JsonInstallResponse {
    mode: &'static str,
    dry_run: bool,
    updated_existing: bool,
    app: JsonInstalledAppInfo,
    removed_obsolete_paths: Vec<String>,
    warnings: Vec<String>,
    cache_outcomes: Vec<JsonCacheOutcomeItem>,
}

#[derive(Serialize)]
struct JsonUninstallResponse {
    mode: &'static str,
    dry_run: bool,
    app: JsonInstalledAppInfo,
    removed_paths: Vec<String>,
    warnings: Vec<String>,
    cache_outcomes: Vec<JsonCacheOutcomeItem>,
}

#[derive(Serialize)]
struct JsonMigrateRegistryResponse {
    mode: &'static str,
    dry_run: bool,
    previous_schema_version: Option<u32>,
    target_schema_version: u32,
    registry_written: bool,
    already_up_to_date: bool,
    total: usize,
    migrated_count: usize,
    unchanged_count: usize,
    failed_count: usize,
    entries: Vec<JsonMigrateRegistryEntryItem>,
}

#[derive(Serialize)]
struct JsonMigrateRegistryEntryItem {
    slug: String,
    name: String,
    status: &'static str,
    ok: bool,
    desktop_hash_added: bool,
    icons_hashed: usize,
    detail: String,
}

pub struct CliDispatcher<'a> {
    extractor: &'a dyn AppImageExtractorPort,
    fs: &'a dyn FileSystemPort,
    registry: &'a dyn RegistryPort,
    desktop_cache: &'a dyn DesktopCachePort,
    system_probe: &'a dyn SystemProbePort,
    clock: &'a dyn ClockPort,
}

impl<'a> CliDispatcher<'a> {
    pub fn new(
        extractor: &'a dyn AppImageExtractorPort,
        fs: &'a dyn FileSystemPort,
        registry: &'a dyn RegistryPort,
        desktop_cache: &'a dyn DesktopCachePort,
        system_probe: &'a dyn SystemProbePort,
        clock: &'a dyn ClockPort,
    ) -> Self {
        Self {
            extractor,
            fs,
            registry,
            desktop_cache,
            system_probe,
            clock,
        }
    }

    pub fn dispatch(
        &self,
        args: CliArgs,
        layout: &XdgLayout,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) -> Result<(), DomainError> {
        self.dispatch_inner(args, layout, stdout, stderr)
            .map_err(DomainError::sanitized)
    }

    fn dispatch_inner(
        &self,
        args: CliArgs,
        layout: &XdgLayout,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) -> Result<(), DomainError> {
        if try_render_static_cli_output(&args, stdout)? {
            return Ok(());
        }

        if args.strict && !args.verify {
            return Err(DomainError::InvalidAppImage {
                path: PathBuf::new(),
                reason: "--strict requires --verify".to_string(),
            });
        }

        if args.doctor {
            let use_case = DoctorUseCase::new(self.system_probe);
            let report = use_case.execute(layout);
            if args.json {
                return write_json_pretty(stdout, &build_json_doctor_response(&report));
            }
            return map_stdout_res(render_doctor_report(&report, stdout));
        }

        if args.list {
            let use_case = ListUseCase::new(self.fs, self.registry);
            let listed = use_case.execute(layout)?;
            if args.json {
                return write_json_pretty(stdout, &build_json_list_response(&listed));
            }
            return map_stdout_res(render_list(&listed, stdout));
        }

        if args.verify {
            let use_case = VerifyUseCase::new(self.fs, self.registry);
            let report = use_case.execute(
                layout,
                &VerifyOptions {
                    target: args.target,
                    strict: args.strict,
                },
            )?;
            if args.json {
                write_json_pretty(stdout, &build_json_verify_response(&report, args.strict))?;
            } else {
                map_stdout_res(render_verify_report(&report, args.strict, stdout))?;
            }
            if !report.all_ok {
                let failed = report
                    .entries
                    .iter()
                    .filter(|entry| entry.status != VerifyEntryStatus::Ok)
                    .count();
                return Err(DomainError::IntegrityVerificationFailed {
                    failed,
                    total: report.entries.len(),
                });
            }
            return Ok(());
        }

        if args.migrate_registry {
            let use_case = MigrateRegistryUseCase::new(self.fs, self.registry);
            let report = use_case.execute(
                layout,
                &MigrateRegistryOptions {
                    dry_run: args.dry_run,
                },
            )?;
            if args.json {
                write_json_pretty(stdout, &build_json_migrate_registry_response(&report))?;
            } else {
                map_stdout_res(render_migrate_registry_report(&report, stdout))?;
            }
            if report.failed_count > 0 {
                return Err(DomainError::RegistryMigrationFailed {
                    failed: report.failed_count,
                    total: report.entries.len(),
                });
            }
            return Ok(());
        }

        let target = args.target.ok_or_else(|| DomainError::InvalidAppImage {
            path: PathBuf::new(),
            reason: "missing APPIMAGE target argument".to_string(),
        })?;

        if args.uninstall {
            let use_case = UninstallUseCase::new(self.fs, self.registry, self.desktop_cache);
            let summary = use_case.execute(
                layout,
                &UninstallOptions {
                    target,
                    dry_run: args.dry_run,
                },
            )?;
            if args.json {
                return write_json_pretty(stdout, &build_json_uninstall_response(&summary));
            }
            for warning in &summary.warnings {
                let _ = writeln!(stderr, "warning: {}", sanitize_terminal_text(warning));
            }
            return map_stdout_res(render_uninstall_summary(&summary, stdout));
        }

        let use_case = InstallUseCase::new(
            self.extractor,
            self.fs,
            self.registry,
            self.desktop_cache,
            self.clock,
        );
        let summary = use_case.execute(
            layout,
            &InstallOptions {
                source_path: PathBuf::from(target),
                move_source: args.move_source,
                custom_name: args.name,
                no_cli: args.no_cli,
                force: args.force,
                dry_run: args.dry_run,
                expected_sha256: args.sha256,
            },
        )?;

        if args.json {
            return write_json_pretty(stdout, &build_json_install_response(&summary));
        }

        for warning in &summary.warnings {
            let _ = writeln!(stderr, "warning: {}", sanitize_terminal_text(warning));
        }
        map_stdout_res(render_install_summary(&summary, stdout))
    }
}

fn write_json_pretty<T: Serialize>(stdout: &mut dyn Write, payload: &T) -> Result<(), DomainError> {
    let serialized = serde_json::to_string_pretty(payload).map_err(|err| DomainError::Io {
        context: "serializing JSON response".to_string(),
        reason: sanitize_for_error(&err.to_string()),
    })?;
    map_stdout_res(writeln!(stdout, "{serialized}"))
}

fn map_stdout_res(res: std::io::Result<()>) -> Result<(), DomainError> {
    match res {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(io_err(err)),
    }
}

fn build_json_app_info(app: &InstalledApp) -> JsonInstalledAppInfo {
    JsonInstalledAppInfo {
        slug: app.slug.as_str().to_string(),
        name: sanitize_terminal_text(&app.name),
        version: app.version.as_deref().map(sanitize_terminal_text),
        appimage_path: safe_display_path(&app.appimage_path),
        stable_symlink_path: app.stable_symlink_path.as_deref().map(safe_display_path),
        cli_symlink_path: app.cli_symlink_path.as_deref().map(safe_display_path),
        desktop_file_path: safe_display_path(&app.desktop_file_path),
        icon_paths: app
            .icon_paths
            .iter()
            .map(|p| safe_display_path(p))
            .collect(),
        sha256: sanitize_terminal_text(&app.sha256),
        installed_at: sanitize_terminal_text(&app.installed_at),
    }
}

fn build_json_cache_outcomes(outcomes: &[CacheRefreshOutcome]) -> Vec<JsonCacheOutcomeItem> {
    outcomes
        .iter()
        .map(|o| JsonCacheOutcomeItem {
            tool: sanitize_terminal_text(&o.tool),
            executed: o.executed,
            detail: sanitize_terminal_text(&o.detail),
        })
        .collect()
}

fn build_json_list_response(items: &[ListedApp]) -> JsonListResponse {
    let apps = items
        .iter()
        .map(|item| {
            let app = &item.app;
            let status = if item.binary_present && item.desktop_present {
                "ok"
            } else if !item.binary_present {
                "missing-binary"
            } else {
                "missing-desktop"
            };
            JsonListedAppItem {
                slug: app.slug.as_str().to_string(),
                name: sanitize_terminal_text(&app.name),
                version: app.version.as_deref().map(sanitize_terminal_text),
                status,
                binary_present: item.binary_present,
                desktop_present: item.desktop_present,
                appimage_path: safe_display_path(&app.appimage_path),
                stable_symlink_path: app.stable_symlink_path.as_deref().map(safe_display_path),
                cli_symlink_path: app.cli_symlink_path.as_deref().map(safe_display_path),
                desktop_file_path: safe_display_path(&app.desktop_file_path),
                icon_paths: app
                    .icon_paths
                    .iter()
                    .map(|p| safe_display_path(p))
                    .collect(),
                sha256: sanitize_terminal_text(&app.sha256),
                installed_at: sanitize_terminal_text(&app.installed_at),
            }
        })
        .collect();
    JsonListResponse { apps }
}

fn build_json_doctor_response(report: &DoctorReport) -> JsonDoctorResponse {
    let checks = report
        .checks
        .iter()
        .map(|check| JsonDoctorCheckItem {
            name: sanitize_terminal_text(&check.name),
            status: match check.status {
                DoctorCheckStatus::Ok => "ok",
                DoctorCheckStatus::Warning => "warning",
                DoctorCheckStatus::Missing => "missing",
            },
            detail: sanitize_terminal_text(&check.detail),
            pacman_package: check.pacman_package.as_deref().map(sanitize_terminal_text),
            remediation: check.remediation.as_deref().map(sanitize_terminal_text),
        })
        .collect();
    JsonDoctorResponse {
        healthy: report.healthy,
        missing_pacman_packages: report
            .missing_pacman_packages
            .iter()
            .map(|p| sanitize_terminal_text(p))
            .collect(),
        checks,
    }
}

fn build_json_verify_response(report: &VerifyReport, strict: bool) -> JsonVerifyResponse {
    let total = report.entries.len();
    let ok_count = report
        .entries
        .iter()
        .filter(|e| e.status == VerifyEntryStatus::Ok)
        .count();
    let failed_count = total.saturating_sub(ok_count);
    let results = report
        .entries
        .iter()
        .map(|entry| JsonVerifiedAppItem {
            slug: entry.slug.as_str().to_string(),
            name: sanitize_terminal_text(&entry.name),
            version: entry.version.as_deref().map(sanitize_terminal_text),
            appimage_path: safe_display_path(&entry.appimage_path),
            status: verify_status_label(entry.status),
            ok: entry.status == VerifyEntryStatus::Ok,
            expected_sha256: sanitize_terminal_text(&entry.expected_sha256),
            actual_sha256: entry.actual_sha256.as_deref().map(sanitize_terminal_text),
            detail: sanitize_terminal_text(&entry.detail),
            artifacts: entry
                .artifact_checks
                .iter()
                .map(|art| JsonVerifyArtifactItem {
                    kind: art.kind,
                    path: safe_display_path(&art.path),
                    ok: art.ok,
                    detail: sanitize_terminal_text(&art.detail),
                })
                .collect(),
        })
        .collect();
    JsonVerifyResponse {
        strict,
        all_ok: report.all_ok,
        total,
        ok_count,
        failed_count,
        results,
    }
}

fn build_json_install_response(summary: &InstallSummary) -> JsonInstallResponse {
    JsonInstallResponse {
        mode: "install",
        dry_run: summary.dry_run,
        updated_existing: summary.updated_existing,
        app: build_json_app_info(&summary.installed_app),
        removed_obsolete_paths: summary
            .removed_obsolete_paths
            .iter()
            .map(|p| safe_display_path(p))
            .collect(),
        warnings: summary
            .warnings
            .iter()
            .map(|w| sanitize_terminal_text(w))
            .collect(),
        cache_outcomes: build_json_cache_outcomes(&summary.cache_outcomes),
    }
}

fn build_json_uninstall_response(summary: &UninstallSummary) -> JsonUninstallResponse {
    JsonUninstallResponse {
        mode: "uninstall",
        dry_run: summary.dry_run,
        app: build_json_app_info(&summary.removed_app),
        removed_paths: summary
            .removed_paths
            .iter()
            .map(|p| safe_display_path(p))
            .collect(),
        warnings: summary
            .warnings
            .iter()
            .map(|w| sanitize_terminal_text(w))
            .collect(),
        cache_outcomes: build_json_cache_outcomes(&summary.cache_outcomes),
    }
}

fn build_json_migrate_registry_response(
    report: &MigrateRegistryReport,
) -> JsonMigrateRegistryResponse {
    let entries = report
        .entries
        .iter()
        .map(|entry| JsonMigrateRegistryEntryItem {
            slug: entry.slug.as_str().to_string(),
            name: sanitize_terminal_text(&entry.name),
            status: match entry.status {
                MigrateRegistryEntryStatus::Migrated => "migrated",
                MigrateRegistryEntryStatus::Unchanged => "unchanged",
                MigrateRegistryEntryStatus::Error => "error",
            },
            ok: entry.status != MigrateRegistryEntryStatus::Error,
            desktop_hash_added: entry.desktop_hash_added,
            icons_hashed: entry.icons_hashed,
            detail: sanitize_terminal_text(&entry.detail),
        })
        .collect();
    JsonMigrateRegistryResponse {
        mode: "migrate_registry",
        dry_run: report.dry_run,
        previous_schema_version: report.previous_schema_version,
        target_schema_version: report.target_schema_version,
        registry_written: report.registry_written,
        already_up_to_date: report.already_up_to_date,
        total: report.entries.len(),
        migrated_count: report.migrated_count,
        unchanged_count: report.unchanged_count,
        failed_count: report.failed_count,
        entries,
    }
}

fn verify_status_label(status: VerifyEntryStatus) -> &'static str {
    match status {
        VerifyEntryStatus::Ok => "ok",
        VerifyEntryStatus::Sha256Mismatch => "sha256_mismatch",
        VerifyEntryStatus::Missing => "missing",
        VerifyEntryStatus::NotRegularFile => "not_regular_file",
        VerifyEntryStatus::UnsafePath => "unsafe_path",
        VerifyEntryStatus::ArtifactError => "artifact_error",
        VerifyEntryStatus::Error => "error",
    }
}

fn safe_display_path(path: &Path) -> String {
    sanitize_terminal_text(&path.to_string_lossy())
}

fn render_install_summary(summary: &InstallSummary, out: &mut dyn Write) -> std::io::Result<()> {
    let prefix = if summary.dry_run { "[DRY-RUN] " } else { "" };
    let action = if summary.updated_existing {
        "Updated"
    } else {
        "Installed"
    };
    let app = &summary.installed_app;

    writeln!(
        out,
        "{prefix}{action} '{}' (slug: {})",
        sanitize_terminal_text(&app.name),
        app.slug.as_str()
    )?;
    if let Some(ref version) = app.version {
        writeln!(out, "  Version:  {}", sanitize_terminal_text(version))?;
    }
    writeln!(out, "  AppImage: {}", safe_display_path(&app.appimage_path))?;
    if let Some(ref stable) = app.stable_symlink_path {
        writeln!(out, "  Symlink:  {}", safe_display_path(stable))?;
    }
    if let Some(ref cli) = app.cli_symlink_path {
        writeln!(out, "  CLI link: {}", safe_display_path(cli))?;
    }
    writeln!(
        out,
        "  Desktop:  {}",
        safe_display_path(&app.desktop_file_path)
    )?;
    if !app.icon_paths.is_empty() {
        writeln!(out, "  Icons ({}):", app.icon_paths.len())?;
        for icon in &app.icon_paths {
            writeln!(out, "    - {}", safe_display_path(icon))?;
        }
    }
    if !summary.removed_obsolete_paths.is_empty() {
        writeln!(
            out,
            "  Cleaned obsolete files ({}):",
            summary.removed_obsolete_paths.len()
        )?;
        for old in &summary.removed_obsolete_paths {
            writeln!(out, "    - {}", safe_display_path(old))?;
        }
    }
    for outcome in &summary.cache_outcomes {
        writeln!(
            out,
            "  Cache [{}]: {}",
            sanitize_terminal_text(&outcome.tool),
            sanitize_terminal_text(&outcome.detail)
        )?;
    }
    Ok(())
}

fn render_uninstall_summary(
    summary: &UninstallSummary,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let prefix = if summary.dry_run { "[DRY-RUN] " } else { "" };
    let verb = if summary.dry_run {
        "Would uninstall"
    } else {
        "Uninstalled"
    };
    writeln!(
        out,
        "{prefix}{verb} '{}' (slug: {})",
        sanitize_terminal_text(&summary.removed_app.name),
        summary.removed_app.slug.as_str()
    )?;
    for path in &summary.removed_paths {
        writeln!(out, "  Removed: {}", safe_display_path(path))?;
    }
    for outcome in &summary.cache_outcomes {
        writeln!(
            out,
            "  Cache [{}]: {}",
            sanitize_terminal_text(&outcome.tool),
            sanitize_terminal_text(&outcome.detail)
        )?;
    }
    Ok(())
}

fn render_list(items: &[ListedApp], out: &mut dyn Write) -> std::io::Result<()> {
    if items.is_empty() {
        writeln!(out, "No AppImages installed via install-appimage.")?;
        return Ok(());
    }

    for item in items {
        let app = &item.app;
        let version = app
            .version
            .as_deref()
            .map(sanitize_terminal_text)
            .unwrap_or_else(|| "-".to_string());
        let state = if item.binary_present && item.desktop_present {
            "ok"
        } else if !item.binary_present {
            "missing-binary"
        } else {
            "missing-desktop"
        };
        writeln!(
            out,
            "{:<24} {:<24} {:<14} [{}] {}",
            app.slug.as_str(),
            sanitize_terminal_text(&app.name),
            version,
            state,
            safe_display_path(&app.appimage_path)
        )?;
    }
    Ok(())
}

fn render_verify_report(
    report: &VerifyReport,
    strict: bool,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    if report.entries.is_empty() {
        writeln!(out, "No AppImages installed via install-appimage.")?;
        return Ok(());
    }

    for entry in &report.entries {
        let badge = match entry.status {
            VerifyEntryStatus::Ok => "OK",
            VerifyEntryStatus::Sha256Mismatch => "MISMATCH",
            VerifyEntryStatus::Missing => "MISSING",
            VerifyEntryStatus::NotRegularFile => "NOT-REGULAR",
            VerifyEntryStatus::UnsafePath => "UNSAFE-PATH",
            VerifyEntryStatus::ArtifactError => "ARTIFACT-ERR",
            VerifyEntryStatus::Error => "ERROR",
        };
        writeln!(
            out,
            "  [{badge:<12}] {:<24} {} ({})",
            entry.slug.as_str(),
            safe_display_path(&entry.appimage_path),
            sanitize_terminal_text(&entry.detail)
        )?;
        for art in &entry.artifact_checks {
            let art_badge = if art.ok { "OK" } else { "FAIL" };
            writeln!(
                out,
                "    - [{art_badge:<4}] {}: {} ({})",
                art.kind,
                safe_display_path(&art.path),
                sanitize_terminal_text(&art.detail)
            )?;
        }
    }

    if report.all_ok {
        if strict {
            writeln!(
                out,
                "\nVerified {} installed AppImage(s) (strict): all checksums and artifacts verified.",
                report.entries.len()
            )?;
        } else {
            writeln!(
                out,
                "\nVerified {} installed AppImage(s): all checksums match.",
                report.entries.len()
            )?;
        }
    }
    Ok(())
}

fn render_doctor_report(report: &DoctorReport, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(out, "install-appimage environment diagnostics:")?;
    for check in &report.checks {
        let badge = match check.status {
            DoctorCheckStatus::Ok => "OK",
            DoctorCheckStatus::Warning => "WARN",
            DoctorCheckStatus::Missing => "MISSING",
        };
        writeln!(
            out,
            "  [{badge:<7}] {:<24} {}",
            sanitize_terminal_text(&check.name),
            sanitize_terminal_text(&check.detail)
        )?;
        if let Some(ref remediation) = check.remediation {
            writeln!(
                out,
                "            -> {}",
                sanitize_terminal_text(remediation)
            )?;
        }
    }

    if !report.missing_pacman_packages.is_empty() {
        writeln!(
            out,
            "\nSuggested Arch Linux / CachyOS package installation:\n  sudo pacman -S {}",
            report.missing_pacman_packages.join(" ")
        )?;
    } else if report.healthy {
        writeln!(out, "\nEnvironment check passed cleanly.")?;
    }
    Ok(())
}

fn render_migrate_registry_report(
    report: &MigrateRegistryReport,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let prefix = if report.dry_run { "[DRY-RUN] " } else { "" };
    if report.entries.is_empty() {
        if report.previous_schema_version == Some(1) {
            let msg = if report.dry_run {
                "Would upgrade empty registry.json from schema v1 to v2."
            } else {
                "Upgraded empty registry.json from schema v1 to v2."
            };
            writeln!(out, "{prefix}{msg}")?;
        } else {
            writeln!(
                out,
                "{prefix}Registry is already up to date (schema v{}).",
                report.target_schema_version
            )?;
        }
        return Ok(());
    }

    for entry in &report.entries {
        let badge = match entry.status {
            MigrateRegistryEntryStatus::Migrated => "MIGRATED",
            MigrateRegistryEntryStatus::Unchanged => "UNCHANGED",
            MigrateRegistryEntryStatus::Error => "ERROR",
        };
        writeln!(
            out,
            "  [{badge:<9}] {:<24} {}",
            entry.slug.as_str(),
            sanitize_terminal_text(&entry.detail)
        )?;
    }

    if report.failed_count > 0 {
        writeln!(
            out,
            "\n{prefix}Migration aborted: {} failed, {} migrated candidate(s), {} unchanged; registry.json was left unmodified.",
            report.failed_count, report.migrated_count, report.unchanged_count
        )?;
    } else if report.already_up_to_date {
        writeln!(
            out,
            "\n{prefix}Registry is already up to date ({} entry/entries in schema v{}).",
            report.unchanged_count, report.target_schema_version
        )?;
    } else if report.dry_run {
        writeln!(
            out,
            "\n{prefix}Would migrate {} entry/entries ({} unchanged) to schema v{}.",
            report.migrated_count, report.unchanged_count, report.target_schema_version
        )?;
    } else {
        writeln!(
            out,
            "\nMigrated {} entry/entries ({} unchanged) to registry.json schema v{}.",
            report.migrated_count, report.unchanged_count, report.target_schema_version
        )?;
    }
    Ok(())
}

fn io_err(err: std::io::Error) -> DomainError {
    DomainError::Io {
        context: "writing CLI output".to_string(),
        reason: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use clap::error::ErrorKind;

    use super::{CliArgs, try_render_static_cli_output};

    #[test]
    fn version_flags_render_cargo_pkg_version() {
        let expected = format!("install-appimage {}\n", env!("CARGO_PKG_VERSION"));
        for flag in ["--version", "-V"] {
            let result = CliArgs::try_parse_from(["install-appimage", flag]);
            assert!(result.is_err());
            if let Err(err) = result {
                assert_eq!(err.kind(), ErrorKind::DisplayVersion);
                assert_eq!(err.to_string(), expected);
            }
        }
    }

    #[test]
    fn parses_and_validates_sha256_verify_json_and_static_generators() {
        let upper = "A".repeat(64);
        let parsed = CliArgs::try_parse_from([
            "install-appimage",
            "--sha256",
            &upper,
            "--dry-run",
            "--json",
            "app.AppImage",
        ])
        .unwrap();
        assert_eq!(parsed.sha256.as_deref(), Some("a".repeat(64).as_str()));
        assert!(parsed.dry_run);
        assert!(parsed.json);

        let bad_sha =
            CliArgs::try_parse_from(["install-appimage", "--sha256", "deadbeef", "a.AppImage"]);
        assert!(bad_sha.is_err());

        let verify_all =
            CliArgs::try_parse_from(["install-appimage", "--verify", "--json"]).unwrap();
        assert!(verify_all.verify);
        assert!(verify_all.json);
        assert!(verify_all.target.is_none());

        let verify_one =
            CliArgs::try_parse_from(["install-appimage", "--verify", "obsidian"]).unwrap();
        assert_eq!(verify_one.target.as_deref(), Some("obsidian"));
        assert!(!verify_one.strict);

        let verify_strict =
            CliArgs::try_parse_from(["install-appimage", "--verify", "--strict", "--json"])
                .unwrap();
        assert!(verify_strict.verify);
        assert!(verify_strict.strict);
        assert!(verify_strict.json);

        assert!(CliArgs::try_parse_from(["install-appimage", "--strict", "a.AppImage"]).is_err());
        assert!(CliArgs::try_parse_from(["install-appimage", "--strict", "--list"]).is_err());

        assert!(
            CliArgs::try_parse_from(["install-appimage", "--verify", "--sha256", &upper]).is_err()
        );
        let migrate = CliArgs::try_parse_from([
            "install-appimage",
            "--migrate-registry",
            "--dry-run",
            "--json",
        ])
        .unwrap();
        assert!(migrate.migrate_registry);
        assert!(migrate.dry_run);
        assert!(migrate.json);
        assert!(
            CliArgs::try_parse_from(["install-appimage", "--migrate-registry", "a.AppImage"])
                .is_err()
        );
        assert!(
            CliArgs::try_parse_from(["install-appimage", "--migrate-registry", "--verify"])
                .is_err()
        );
        assert!(
            CliArgs::try_parse_from(["install-appimage", "--migrate-registry", "--list"]).is_err()
        );
        assert!(
            CliArgs::try_parse_from(["install-appimage", "--migrate-registry", "--doctor"])
                .is_err()
        );
        assert!(CliArgs::try_parse_from(["install-appimage", "--migrate-registry", "-u"]).is_err());
        assert!(
            CliArgs::try_parse_from(["install-appimage", "--migrate-registry", "--strict"])
                .is_err()
        );
        assert!(
            CliArgs::try_parse_from(["install-appimage", "--migrate-registry", "--sha256", &upper])
                .is_err()
        );
        assert!(CliArgs::try_parse_from(["install-appimage", "--generate-man", "--json"]).is_err());
        assert!(
            CliArgs::try_parse_from([
                "install-appimage",
                "--generate-completion",
                "bash",
                "--list",
            ])
            .is_err()
        );

        let comp_args =
            CliArgs::try_parse_from(["install-appimage", "--generate-completion", "bash"]).unwrap();
        let mut comp_out = Vec::new();
        assert!(try_render_static_cli_output(&comp_args, &mut comp_out).unwrap());
        assert!(!comp_out.is_empty());

        let man_args = CliArgs::try_parse_from(["install-appimage", "--generate-man"]).unwrap();
        let mut man_out = Vec::new();
        assert!(try_render_static_cli_output(&man_args, &mut man_out).unwrap());
        assert!(String::from_utf8_lossy(&man_out).contains(".TH install-appimage"));
    }

    #[test]
    fn static_generators_handle_broken_pipe_without_panicking() {
        struct BrokenPipeWriter;

        impl std::io::Write for BrokenPipeWriter {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pipe closed",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pipe closed",
                ))
            }
        }

        let comp_args =
            CliArgs::try_parse_from(["install-appimage", "--generate-completion", "bash"]).unwrap();
        let mut writer = BrokenPipeWriter;
        assert_eq!(
            try_render_static_cli_output(&comp_args, &mut writer),
            Ok(true)
        );

        let man_args = CliArgs::try_parse_from(["install-appimage", "--generate-man"]).unwrap();
        assert_eq!(
            try_render_static_cli_output(&man_args, &mut writer),
            Ok(true)
        );
    }
}

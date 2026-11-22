# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-11-22

### Fixed

- Restricted direct and stem-based icon candidate matching in `extract_icons` to `.png`/`.svg` filenames (preserving `.DirIcon` fallback), preventing extensionless desktop `Icon=<app>` keys (e.g., `Icon=bruno` matching a 201 MB root ELF binary) from probing application binaries as icons.
- Made oversized icon candidate handling resilient by skipping individual `ResourceLimitExceeded` reads (e.g., `> 8 MiB` icon entries or exhausted remaining budget) instead of aborting AppImage metadata extraction when valid smaller icons exist.

## [0.2.0] - 2026-11-21

### Added

- Structured deterministic `--json` output across `-l`/`--list`, `--doctor`, `--verify`, `--dry-run`, install, and uninstall commands.
- Shell completion generation via `--generate-completion <SHELL>` (`clap_complete`) and roff manpage generation via `--generate-man` (`clap_mangen`), working without requiring `HOME`.
- Hybrid `install.sh` and `uninstall.sh` scripts supporting user-level XDG (`~/.local`), `--system` (`/usr/local`), `--prefix`, local `cargo build --release --locked` (`--source`), prebuilt GitHub Release downloads with mandatory `SHA256SUMS.txt` verification (`--release`, `--version`, `--repo`), `--bin`, and `--dry-run`, while preserving `~/Applications` and `registry.json` on uninstall.
- Streaming SHA-256 verification on installation (`--sha256 <HEX>`), validating 64 hexadecimal characters case-insensitively and aborting before any writes or payload parsing on mismatch.
- Installed AppImage integrity verification command (`--verify [APPIMAGE]`), validating XDG containment, `O_NOFOLLOW | O_NONBLOCK`/regular file checks, and streaming SHA-256 digests against `registry.json` (returning non-zero exit status on any discrepancy, missing file, or integrity failure), plus `--verify --strict` to verify symlinks as well as `.desktop` and icon presence and SHA-256 content digests.
- `registry.json` schema v2 (`desktop_file_sha256` and `icon_sha256s` with strict hex/canonical-path validation) preserving backwards-compatible deserialization of schema v1 registries, plus `--migrate-registry` (supporting `--dry-run` and `--json`) to idempotently backfill schema v2 artifact hashes via `O_NOFOLLOW | O_NONBLOCK` without reinstalling or partially overwriting on errors.
- Canonical path normalization of duplicate (`//`) and trailing (`/`) slashes in `HOME` and `XDG_DATA_HOME` environment inputs in `XdgLayout::try_from_env_values`.
- Pure-Rust, zero-dependency, zero-`unsafe` (`#![forbid(unsafe_code)]`) ISO9660 parser (`ECMA-119` PVD + Rock Ridge `NM`/`SL`/`PX`/`CE`/`CL`/`RE` + Joliet SVD fallback) with strict AppSec read, depth, directory, extent-loop, path traversal, and symlink containment budgets for legacy Type 1 AppImages.
- Automatic FreeDesktop Desktop Menu Specification `Categories=` deduplication and normalization (`Utility` removal when paired with specific main categories, automatic `AudioVideo` pairing when `Audio` or `Video` is present).
- Standalone `cargo-fuzz` workspace in `fuzz/` with targets `elf`, `desktop_entry`, `svg_sanitizer`, and `iso9660` and initial seed corpus under `fuzz/corpus/`.
- Crate-wide `#![forbid(unsafe_code)]` enforcement, `O_NONBLOCK` FIFO/TOCTOU hardening on `open()`, and `deny.toml` supply-chain policy compatibility.

### Changed

- Bumped crate version to `0.2.0`.
- Updated `--doctor` diagnostics and documentation to reflect zero external dependencies for Type 1 ISO9660 extraction.

### Removed

- Removed external `bsdtar` (`libarchive`) subprocess execution and dependency checks for Type 1 ISO9660 AppImages.

## [0.1.0] - 2026-11-21

### Added

- Initial release of `install-appimage` CLI (`0.1.0`) with user-level XDG installation (no `sudo` required).
- Static zero-execution AppImage Type 2 metadata extraction via pure-Rust ELF header/section parser and `backhand` SquashFS reader (`gzip`, `xz`, `zstd`, `lz4`) with SuperBlock pre-validation and read budgets, plus hardened read-only `bsdtar` support for verified `CD001` Type 1 ISO9660 AppImages and fail-closed rejection of DwarFS payloads.
- Strict security protections against archive path traversal, symlink escape, `O_NOFOLLOW` / SHA-256 staged verification against `--move`/source TOCTOU, symlink-free XDG ancestor verification, strict `registry.json` layout validation, structural XML/SVG allowlist validation (anti-XSS/XXE/SMIL/SSRF), ANSI/BiDi/Unicode-Tag terminal neutralization, and FreeDesktop Layer-1/Layer-2 `.desktop` sanitization (`Type=Application`, `Exec=` stable symlink + single allowlisted `%f`/`%F`/`%u`/`%U`).
- Clean atomic install, update (with obsolete file/icon cleanup), and uninstall via JSON state registry (`$XDG_DATA_HOME/install-appimage/registry.json`).
- Full CLI interface: `<APPIMAGE>` (`--move`, `--name`, `--no-cli`, `--force`, `--dry-run`), `-u`/`--uninstall` (`--dry-run` + `<APPIMAGE>` target), `-l`/`--list`, `--doctor`, and `--version`/`-V`.
- Graceful desktop cache integration (`desktop-file-validate`, `update-desktop-database`, `gtk-update-icon-cache`, `kbuildsycoca6`/`kbuildsycoca5`) and Arch Linux / CachyOS environment diagnostics (`--doctor`).
- Unit, component, and real SquashFS/CLI integration test suites (`cargo test`).

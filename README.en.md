# install-appimage

> 🌐 **Languages:** [🇧🇷 Português](README.md) | 🇺🇸 **English** | [🇪🇸 Español](README.es.md) | [🇨🇳 简体中文](README.zh-CN.md)

A Rust CLI manager for installing, updating, verifying integrity, diagnosing, listing, and uninstalling **AppImages** on Linux (with a focus on **Arch Linux** and **CachyOS**) using strictly user-level XDG integration (**no `sudo`**).

---

## Table of Contents

- [Key Features](#key-features)
- [Security and Extraction Model](#security-and-extraction-model)
- [Prerequisites and Installation](#prerequisites-and-installation)
- [User File Layout (XDG)](#user-file-layout-xdg)
- [Usage Guide](#usage-guide)
- [Environment Diagnostics (`--doctor`)](#environment-diagnostics---doctor)
- [Development, Fuzzing, and Tests](#development-fuzzing-and-tests)
- [License](#license)

---

## Key Features

- **User-level installation without `sudo`:** copies (default) or moves (`--move`) the AppImage file to `~/Applications/`, sets executable permissions (`0755`), and maintains a stable symlink `~/Applications/<slug>.AppImage`.
- **Terminal shortcut (`PATH`):** creates a CLI symlink at `~/.local/bin/<slug>` pointing to the stable symlink (can be disabled with `--no-cli`).
- **System menu integration:** extracts icons (`.png` into `hicolor` size directories + `.svg` into `scalable`), normalizes `Categories=` per the FreeDesktop Desktop Menu Specification (deduplicating, removing redundant `Utility` alongside specific main categories, and ensuring `AudioVideo` when `Audio`/`Video` are present), and generates `~/.local/share/applications/<slug>.desktop`.
- **Cryptographic integrity verification (`--sha256` and `--verify`):** validates the SHA-256 checksum in streaming mode before any writes during installation (`--sha256 <HEX>`) and audits binaries already installed in `~/Applications/` against `registry.json` (`--verify`, or `--verify --strict` to also validate SHA-256 contents of `.desktop` and icons stored in registry schema v2 and symlink consistency).
- **Explicit v1 → v2 registry migration (`--migrate-registry`):** upgrades `registry.json` entries created in v0.1.0 to schema v2 by computing streaming (`O_NOFOLLOW | O_NONBLOCK`) SHA-256 hashes of already-installed `.desktop` and icon files without needing to reinstall the AppImage (supports `--dry-run`, `--json`, and is idempotent).
- **Structured JSON output (`--json`):** emits deterministic JSON output to `stdout` for `-l`/`--list`, `--doctor`, `--verify`, `--migrate-registry`, `--dry-run`, install, and uninstall — ideal for Waybar, Rofi, and automation scripts.
- **Shell completions and manpage (`--generate-completion` / `--generate-man`):** generates native completion scripts for `bash`, `zsh`, `fish`, `elvish`, and `powershell`, as well as a `roff` manual page directly to `stdout`.
- **Clean updates with no orphan files:** when installing a new version of an already-registered app, automatically removes the old binary and obsolete icons after completing the new installation.
- **Surgical uninstallation (`-u` / `--uninstall`):** accepts the app name, slug, or `.AppImage` file path/filename, removing only the tracked files within the user's XDG directories.
- **Safe dry-run (`--dry-run`):** shows exactly what would be installed, updated, or removed without modifying any files on disk.
- **Automatic desktop cache updates:** runs `desktop-file-validate`, `update-desktop-database`, `gtk-update-icon-cache`, and `kbuildsycoca6`/`kbuildsycoca5` when present on the host (gracefully degrading if any are missing).
- **System diagnostics (`--doctor`):** checks FUSE 2/3, XDG tools, `PATH`, and local directories, suggesting the exact `pacman` packages when anything is missing.

---

## Security and Extraction Model

- **Zero execution of untrusted binaries on installation:**
  - **AppImage Type 2 (ELF + SquashFS):** the post-ELF offset is calculated via a pure-Rust ELF parser and only the required metadata (`.desktop`, `.DirIcon`, and icons) is read directly from SquashFS (`gzip`, `xz`, `zstd`, `lz4`) without ever executing the AppImage binary (`--appimage-extract` is not invoked).
  - **AppImage Type 1 (ISO9660):** native pure-Rust, zero-dependency, `unsafe`-free ISO9660 parser (ECMA-119 PVD + Rock Ridge `NM`/`SL`/`PX`/`CE`/`CL`/`RE` + Joliet SVD fallback), with no external subprocess (`bsdtar` is not required) and with hard budgets against directory/extent loops, traversal, and symlinks escaping the root.
  - **Fail-closed:** payloads that cannot be read statically (such as DwarFS) are safely rejected without executing ELF code.
- **Protection against path traversal, symlink escape, TOCTOU, and unsafe code (`#![forbid(unsafe_code)]`):** compiled with strict prohibition of `unsafe`, path component validation, rejection of `..` escapes, `NUL` bytes, Unicode BiDi/Tags characters, opening via `O_NOFOLLOW | O_NONBLOCK` without following symlinks or blocking on FIFOs at source/registry/verification, pre-install streaming `--sha256` check, SHA-256 verification during staging, blocking symlinked directories under XDG roots, strict schema v2 validation (with backward-compatible v1 reading) and path/hash integrity in `registry.json`, and dependency governance via `deny.toml` (`cargo-deny`) + `cargo-audit` in CI.
- **`.desktop` sanitization and anti-command-injection:**
  - Enforces mandatory `Type=Application` and rejects duplicate `[Desktop Entry]` blocks, `[Desktop Action ...]` groups, `DBusActivatable`, and `Path=`.
  - Strips ANSI sequences (`CSI`/`OSC`/`DCS`/`APC`), control characters, and BiDi characters from text fields, JSON, and terminal output.
  - Completely replaces the original `Exec=` command with the escaped path of the stable symlink (with full Layer 1 + Layer 2 composition compatible with `GLib.KeyFile` / `desktop-file-validate`), preserving at most a single allowlisted XDG field code (`%f`, `%F`, `%u`, or `%U`).
  - Validates SVG icons using a structural XML parser with a strict allowlist (rejects `<!DOCTYPE>`/`<!ENTITY>` XXE, PIs such as `<?xml-stylesheet?>`, `xi:include`, `<script>`, `<foreignObject>`, `on*` attributes, SMIL mutating `href`/`on*`, and any external/active URI or non-local CSS `url()`/`@import`).
- **Atomic writes and collision protection:** uses temporary files and atomic `rename` in the same directory; refuses to overwrite unmanaged files without `--force` and blocks collisions with files belonging to another managed application.

---

## Prerequisites and Installation

### Prerequisites (Arch Linux / CachyOS)

To run AppImages and update desktop environment caches:

```bash
sudo pacman -S fuse2 fuse3 desktop-file-utils gtk-update-icon-cache
```

Optional depending on your environment:
- `kservice` (`kbuildsycoca6`) to update the KDE Plasma menu cache.

### Quick Installation via GitHub Release (`install.sh`)

The `install.sh` script automatically detects your architecture (`x86_64` / `aarch64`), downloads the static (`musl`) tarball from GitHub Releases, strictly verifies the checksum via `SHA256SUMS.txt`, and installs the binary, completions (`bash`, `zsh`, `fish`), and manpage at the user level (`~/.local`):

```bash
curl -fsSL https://raw.githubusercontent.com/passella/install-appimage/master/install.sh | bash -s -- --repo passella/install-appimage --release
```

Main `install.sh` options:
- `--release`: downloads the pre-built binary from GitHub Releases (default outside the repository; use `--version <vX.Y.Z>` to pin a tag, `--repo <OWNER/REPO>` / `INSTALL_APPIMAGE_REPO`, or `INSTALL_APPIMAGE_RELEASE_BASE_URL` for mirrors/local testing).
- `--source`: compiles locally via `cargo build --release --locked` (default when run inside the repository).
- `--bin <PATH>`: installs an already-compiled local binary.
- `--system`: installs system-wide into `/usr/local` (uses `sudo` only when necessary).
- `--prefix <DIR>`: installs into a custom prefix (`<DIR>/bin`, `<DIR>/share`).
- `--no-completions` / `--no-man`: skips installing shell completions or the manual page.
- `--dry-run`: displays all planned actions without modifying the filesystem.

### Building and Installing from Source

Requires a Rust toolchain supporting **Rust Edition 2024**:

```bash
git clone https://github.com/passella/install-appimage.git
cd install-appimage
./install.sh
```

Or directly via Cargo (without automatic completions/manpage):

```bash
cargo install --path .
```

Ensure `~/.local/bin` (or `~/.cargo/bin`) is in your `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Uninstalling the CLI (`uninstall.sh`)

To remove the binary, completions, and manpage installed by `install.sh`:

```bash
./uninstall.sh
```

Supported options: `--system`, `--prefix <DIR>`, and `--dry-run`.

> **Note:** `uninstall.sh` only removes the `install-appimage` CLI, its completions, and its manpage. Your managed AppImages in `~/Applications/` and the registry `~/.local/share/install-appimage/registry.json` remain **preserved** (to remove a specific AppImage beforehand, use `install-appimage -u <app>`).

---

## User File Layout (XDG)

| Artifact | Default Location (respects `XDG_DATA_HOME`) |
| --- | --- |
| AppImage binary (`chmod 755`) | `~/Applications/<file>.AppImage` |
| Stable symlink | `~/Applications/<slug>.AppImage` *(omitted when the file already has this exact name)* |
| CLI shortcut in `PATH` | `~/.local/bin/<slug>` *(omitted with `--no-cli`)* |
| Desktop entry | `~/.local/share/applications/<slug>.desktop` |
| Icons (`png` / `svg`) | `~/.local/share/icons/hicolor/<size>/apps/<slug>.<ext>` or `scalable/apps/<slug>.svg` |
| State registry | `~/.local/share/install-appimage/registry.json` |

---

## Usage Guide

### Syntax

```text
install-appimage [OPTIONS] [APPIMAGE]
```

### Options and Flags

| Option | Description |
| --- | --- |
| `<APPIMAGE>` | Path to the `.AppImage` file to install/update (or app name, slug, or file path when used with `-u`/`--uninstall` or `--verify`). |
| `--move` | Moves the `.AppImage` file into `~/Applications/` instead of copying it. |
| `--name <NAME>` | Overrides the application display name and the derived `<slug>`. |
| `--no-cli` | Does not create the terminal symlink at `~/.local/bin/<slug>`. |
| `--force` | Forces overwriting an existing unmanaged file or symlink at the destination. |
| `--sha256 <HEX>` | Validates the expected SHA-256 hash (64 hex digits) in streaming mode before installing/simulating. |
| `--dry-run` | Simulates all install or uninstall operations without modifying the filesystem. |
| `-u`, `--uninstall` | Uninstalls a managed AppImage (provide the name, slug, or `.AppImage` file path/filename in `<APPIMAGE>`). |
| `-l`, `--list` | Lists AppImages installed and managed by `install-appimage`. |
| `--verify` | Verifies the SHA-256 integrity and path safety of installed AppImages (or a specific app) against `registry.json`. Returns a non-zero exit code on mismatches. |
| `--strict` | Used with `--verify`: also validates SHA-256 integrity (schema v2) and path containment of `.desktop`, icons, and stable/CLI symlinks against `registry.json`. |
| `--migrate-registry` | Upgrades `registry.json` from schema v1 to v2 by computing streaming (`O_NOFOLLOW \| O_NONBLOCK`) hashes of existing `.desktop` and icon files without reinstalling. Compatible with `--dry-run` and `--json`. |
| `--doctor` | Runs Arch Linux / CachyOS environment diagnostics and suggests missing `pacman` packages. |
| `--json` | Emits structured, deterministic JSON output to `stdout` (`-l`, `--doctor`, `--verify`, `--migrate-registry`, `--dry-run`, install, and uninstall). |
| `--generate-completion <SHELL>` | Prints the shell completion script for `<SHELL>` (`bash`, `zsh`, `fish`, `elvish`, `powershell`) to `stdout`. |
| `--generate-man` | Prints the manual page in `roff` format to `stdout`. |
| `-h`, `--help` | Displays full CLI help. |
| `-V`, `--version` | Displays the tool version (`0.2.1`). |

### Practical Examples

```bash
# Install while verifying the official SHA-256 before any writes
install-appimage --sha256 0123456789abcdef... ./Obsidian-1.7.4.AppImage

# Install by moving the original file and customizing the name/slug
install-appimage --move --name "Obsidian Notes" ./Obsidian-1.7.4.AppImage

# Install only in the desktop menu, without creating a link in ~/.local/bin
install-appimage --no-cli ./MyApp.AppImage

# Simulate installation with JSON output for automation
install-appimage --dry-run --json ./MyApp.AppImage

# Force overwrite if an untracked file already exists at the destination
install-appimage --force ./MyApp.AppImage

# List managed AppImages (human-readable or JSON for Rofi/Waybar)
install-appimage -l
install-appimage -l --json

# Verify SHA-256 integrity of all installed AppImages (or strict audit of all artifacts)
install-appimage --verify
install-appimage --verify --strict --json
install-appimage --verify obsidian --json

# Migrate legacy registry.json (schema v1 -> v2) without reinstalling AppImages
install-appimage --migrate-registry --dry-run --json
install-appimage --migrate-registry --json

# Uninstall by slug, name, or file path
install-appimage -u obsidian
install-appimage -u "Obsidian Notes"
install-appimage -u ~/Applications/Obsidian-1.7.4.AppImage

# Simulate uninstallation
install-appimage -u --dry-run obsidian

# Diagnose dependencies on Arch Linux / CachyOS (human-readable or JSON)
install-appimage --doctor
install-appimage --doctor --json
```

---

## Environment Diagnostics (`--doctor`)

The `install-appimage --doctor` command checks:

1. Execution privileges (warns if run via `sudo`/root).
2. Presence of `libfuse.so.2` (`fuse2`) and `libfuse3.so.3` / `fusermount3` (`fuse3`).
3. Presence of `desktop-file-validate` and `update-desktop-database` (`desktop-file-utils`).
4. Presence of `gtk-update-icon-cache` (`gtk-update-icon-cache`).
5. Presence of `kbuildsycoca6` / `kbuildsycoca5` (`kservice`, optional for KDE Plasma).
6. Inclusion of `~/.local/bin` in the `PATH` variable.
7. Write/create permissions for the user's XDG directories.

If any package is missing, the command prints the exact recommended `sudo pacman -S ...` command (and exposes `missing_pacman_packages` in `--json` mode).

---

## Development, Fuzzing, and Tests

Run formatting, strict linting, unit/component/integration tests, and release build:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Fuzzing targets (`cargo-fuzz` + `nightly`) and seed corpora (`fuzz/corpus/`) are isolated under `fuzz/`:

```bash
cargo +nightly fuzz run elf
cargo +nightly fuzz run desktop_entry
cargo +nightly fuzz run svg_sanitizer
cargo +nightly fuzz run iso9660
```

---

## License

Distributed under the **MIT** license. See [LICENSE](LICENSE) for details.

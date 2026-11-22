# install-appimage

> 🌐 **语言:** [🇧🇷 Português](README.md) | [🇺🇸 English](README.en.md) | [🇪🇸 Español](README.es.md) | 🇨🇳 **简体中文**

使用 Rust 编写的 CLI 管理器，用于以**纯用户级** XDG 集成（**无需 `sudo`**）在 Linux（重点支持 **Arch Linux** 和 **CachyOS**）上安装、更新、校验完整性、诊断、列出和卸载 **AppImage**。

---

## 目录

- [核心功能](#核心功能)
- [安全性与提取模型](#安全性与提取模型)
- [前置条件与安装](#前置条件与安装)
- [用户文件布局 (XDG)](#用户文件布局-xdg)
- [使用指南](#使用指南)
- [环境诊断 (`--doctor`)](#环境诊断---doctor)
- [开发、模糊测试与测试](#开发模糊测试与测试)
- [许可证](#许可证)

---

## 核心功能

- **无需 `sudo` 的用户级安装：** 将 AppImage 文件复制（默认）或移动（`--move`）到 `~/Applications/`，赋予可执行权限（`0755`），并维护一个稳定的符号链接 `~/Applications/<slug>.AppImage`。
- **终端快捷命令（`PATH`）：** 在 `~/.local/bin/<slug>` 创建指向稳定符号链接的 CLI 符号链接（可通过 `--no-cli` 禁用）。
- **系统菜单集成：** 提取图标（`hicolor` 尺寸的 `.png` + `scalable` 中的 `.svg`），根据 FreeDesktop Desktop Menu 规范标准化 `Categories=`（去重、在存在更具体的主类别时移除冗余的 `Utility`，并在存在 `Audio`/`Video` 时确保包含 `AudioVideo`），并生成 `~/.local/share/applications/<slug>.desktop`。
- **加密完整性校验（`--sha256` 与 `--verify`）：** 在安装前以流式方式校验 SHA-256 校验和，确保在任何磁盘写入之前完成验证（`--sha256 <HEX>`）；并根据 `registry.json` 审计 `~/Applications/` 中已安装的二进制文件（`--verify`，或使用 `--verify --strict` 进一步校验注册表 schema v2 中存储的 `.desktop` 和图标的 SHA-256 内容及符号链接一致性）。
- **显式注册表迁移 v1 → v2（`--migrate-registry`）：** 将 v0.1.0 创建的 `registry.json` 记录升级为 schema v2，通过流式读取（`O_NOFOLLOW | O_NONBLOCK`）计算已安装 `.desktop` 与图标的 SHA-256 哈希，无需重新安装 AppImage（支持 `--dry-run`、`--json`，且具有幂等性）。
- **结构化 JSON 输出（`--json`）：** 为 `-l`/`--list`、`--doctor`、`--verify`、`--migrate-registry`、`--dry-run`、安装和卸载操作向 `stdout` 输出确定性的 JSON —— 非常适合 Waybar、Rofi 及自动化脚本。
- **Shell 自动补全与手册页（`--generate-completion` / `--generate-man`）：** 直接向 `stdout` 生成适用于 `bash`、`zsh`、`fish`、`elvish` 和 `powershell` 的原生补全脚本，以及 `roff` 格式的手册页。
- **无残留的干净更新：** 安装已注册应用的新版本时，会在新安装完成后自动删除旧版二进制文件和过时图标。
- **精准卸载（`-u` / `--uninstall`）：** 支持按应用名称、slug 或 `.AppImage` 文件路径/文件名卸载，仅移除用户 XDG 目录中受追踪的文件。
- **安全模拟运行（`--dry-run`）：** 准确展示将要安装、更新或删除的内容，而不修改磁盘上的任何文件。
- **自动刷新桌面缓存：** 当宿主机上存在 `desktop-file-validate`、`update-desktop-database`、`gtk-update-icon-cache` 和 `kbuildsycoca6`/`kbuildsycoca5` 时自动运行（若某项缺失则优雅降级）。
- **系统诊断（`--doctor`）：** 检查 FUSE 2/3、XDG 工具、`PATH` 及本地目录，并在缺少依赖时给出精确的 `pacman` 安装包建议。

---

## 安全性与提取模型

- **安装过程零执行不可信二进制文件：**
  - **AppImage Type 2（ELF + SquashFS）：** 通过纯 Rust 的 ELF 解析器计算 ELF 之后的偏移量，直接从 SquashFS（`gzip`、`xz`、`zstd`、`lz4`）中仅读取所需的元数据（`.desktop`、`.DirIcon` 和图标），绝不执行 AppImage 二进制文件（不会调用 `--appimage-extract`）。
  - **AppImage Type 1（ISO9660）：** 零依赖、无 `unsafe` 的纯 Rust 原生 ISO9660 解析器（ECMA-119 PVD + Rock Ridge `NM`/`SL`/`PX`/`CE`/`CL`/`RE` + Joliet SVD 回退），无需外部子进程（不需要 `bsdtar`），并内置针对目录/extent 循环、路径遍历和逃逸根目录的符号链接的严格预算限制（hard budgets）。
  - **故障安全关闭（Fail-closed）：** 对于无法静态读取的载荷（例如 DwarFS），在不执行任何 ELF 代码的前提下安全拒绝。
- **防范路径遍历、符号链接逃逸、TOCTOU 与不安全代码（`#![forbid(unsafe_code)]`）：** 编译期严格禁止 `unsafe`，校验路径组件，拒绝 `..` 逃逸、`NUL` 字节、Unicode BiDi/Tags 字符；在读取源文件、注册表和执行校验时使用 `O_NOFOLLOW | O_NONBLOCK` 打开文件，不跟随符号链接且不在 FIFO 上阻塞；安装前执行流式 `--sha256` 校验；暂存（staging）阶段校验 SHA-256；禁止在 XDG 根目录下使用符号链接目录；严格校验 schema v2（同时向后兼容读取 v1）及 `registry.json` 中的路径/哈希完整性；并在 CI 中通过 `deny.toml`（`cargo-deny`）+ `cargo-audit` 治理依赖。
- **`.desktop` 清理与防命令注入：**
  - 强制要求 `Type=Application`，拒绝重复的 `[Desktop Entry]` 块、`[Desktop Action ...]` 分组、`DBusActivatable` 和 `Path=`。
  - 从文本字段、JSON 和终端输出中剥离 ANSI 转义序列（`CSI`/`OSC`/`DCS`/`APC`）、控制字符和 BiDi 字符。
  - 将原始 `Exec=` 命令完全替换为经转义的稳定符号链接路径（完整组合 Layer 1 + Layer 2 转义，兼容 `GLib.KeyFile` / `desktop-file-validate`），最多仅保留一个来自白名单的 XDG *field code*（`%f`、`%F`、`%u` 或 `%U`）。
  - 使用严格白名单结构化 XML 解析器校验 SVG 图标（拒绝 `<!DOCTYPE>`/`<!ENTITY>` XXE、如 `<?xml-stylesheet?>` 等处理指令、`xi:include`、`<script>`、`<foreignObject>`、`on*` 属性、修改 `href`/`on*` 的 SMIL 动画，以及任何外部/活动 URI 或非本地 CSS `url()`/`@import`）。
- **原子写入与冲突防护：** 使用临时文件并在同一目录下执行原子 `rename`；在未使用 `--force` 时拒绝覆盖未受管文件，并阻止与属于其他受管应用的文件发生冲突。

---

## 前置条件与安装

### 前置条件 (Arch Linux / CachyOS)

用于运行 AppImage 并刷新桌面环境缓存：

```bash
sudo pacman -S fuse2 fuse3 desktop-file-utils gtk-update-icon-cache
```

按桌面环境可选：
- `kservice`（`kbuildsycoca6`）：用于更新 KDE Plasma 的菜单缓存。

### 通过 GitHub Release 快速安装 (`install.sh`)

`install.sh` 脚本会自动检测系统架构（`x86_64` / `aarch64`），从 GitHub Releases 下载静态编译的压缩包（`musl`），强制通过 `SHA256SUMS.txt` 校验文件哈希，并将二进制文件、自动补全脚本（`bash`、`zsh`、`fish`）及手册页安装到用户目录（`~/.local`）：

```bash
curl -fsSL https://raw.githubusercontent.com/passella/install-appimage/master/install.sh | bash -s -- --repo passella/install-appimage --release
```

`install.sh` 主要选项：
- `--release`：从 GitHub Releases 下载预编译二进制文件（在仓库外部运行时为默认行为；可使用 `--version <vX.Y.Z>` 指定标签版本、`--repo <OWNER/REPO>` / `INSTALL_APPIMAGE_REPO`，或使用 `INSTALL_APPIMAGE_RELEASE_BASE_URL` 指定镜像源或本地测试地址）。
- `--source`：通过 `cargo build --release --locked` 在本地编译（在仓库目录内运行时为默认行为）。
- `--bin <PATH>`：安装本地已编译的二进制文件。
- `--system`：全局安装到 `/usr/local`（仅在必要时使用 `sudo`）。
- `--prefix <DIR>`：安装到自定义前缀目录（`<DIR>/bin`、`<DIR>/share`）。
- `--no-completions` / `--no-man`：跳过安装自动补全脚本或手册页。
- `--dry-run`：展示所有计划执行的操作，但不修改文件系统。

### 从源码编译与安装

需要支持 **Rust Edition 2024** 的 Rust 工具链：

```bash
git clone https://github.com/passella/install-appimage.git
cd install-appimage
./install.sh
```

或直接使用 Cargo 安装（不会自动安装自动补全脚本与手册页）：

```bash
cargo install --path .
```

请确保 `~/.local/bin`（或 `~/.cargo/bin`）已添加到你的 `PATH` 环境变量中：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 卸载 CLI (`uninstall.sh`)

移除由 `install.sh` 安装的二进制文件、自动补全脚本和手册页：

```bash
./uninstall.sh
```

支持的选项：`--system`、`--prefix <DIR>` 和 `--dry-run`。

> **注意：** `uninstall.sh` 仅移除 `install-appimage` CLI 工具、其自动补全脚本和手册页。你在 `~/Applications/` 中受管理的 AppImage 文件以及注册表 `~/.local/share/install-appimage/registry.json` 将**保留不变**（如需先移除某个特定 AppImage，请使用 `install-appimage -u <app>`）。

---

## 用户文件布局 (XDG)

| 产物 | 默认位置（遵循 `XDG_DATA_HOME`） |
| --- | --- |
| AppImage 二进制文件（`chmod 755`） | `~/Applications/<文件>.AppImage` |
| 稳定符号链接 | `~/Applications/<slug>.AppImage` *（当文件名已完全一致时省略）* |
| `PATH` 中的 CLI 快捷方式 | `~/.local/bin/<slug>` *（使用 `--no-cli` 时省略）* |
| 桌面入口文件 | `~/.local/share/applications/<slug>.desktop` |
| 图标（`png` / `svg`） | `~/.local/share/icons/hicolor/<size>/apps/<slug>.<ext>` 或 `scalable/apps/<slug>.svg` |
| 状态注册表 | `~/.local/share/install-appimage/registry.json` |

---

## 使用指南

### 语法

```text
install-appimage [选项] [APPIMAGE]
```

### 选项与标志

| 选项 | 说明 |
| --- | --- |
| `<APPIMAGE>` | 要安装/更新的 `.AppImage` 文件路径（与 `-u`/`--uninstall` 或 `--verify` 一起使用时，也可为应用名称、slug 或文件名/路径）。 |
| `--move` | 将 `.AppImage` 文件移动到 `~/Applications/`，而不是复制。 |
| `--name <NAME>` | 覆盖应用的显示名称及由此派生的 `<slug>`。 |
| `--no-cli` | 不在 `~/.local/bin/<slug>` 创建终端符号链接。 |
| `--force` | 强制覆盖目标位置已存在的未受管文件或符号链接。 |
| `--sha256 <HEX>` | 在安装或模拟运行前，以流式方式校验预期的 SHA-256 哈希（64 位十六进制字符）。 |
| `--dry-run` | 模拟所有安装或卸载操作，不修改文件系统。 |
| `-u`, `--uninstall` | 卸载受管理的 AppImage（在 `<APPIMAGE>` 中传入应用名称、slug 或 `.AppImage` 文件路径/名称）。 |
| `-l`, `--list` | 列出由 `install-appimage` 安装和管理的 AppImage。 |
| `--verify` | 对照 `registry.json` 校验已安装 AppImage（或特定应用）的 SHA-256 完整性及路径安全性。若发现不一致则返回非零退出码。 |
| `--strict` | 与 `--verify` 配合使用：进一步对照 `registry.json` 校验 `.desktop`、图标的 SHA-256 完整性（schema v2）以及稳定符号链接/CLI 符号链接的约束性。 |
| `--migrate-registry` | 将 `registry.json` 从 schema v1 升级到 v2，通过流式读取（`O_NOFOLLOW \| O_NONBLOCK`）计算现有 `.desktop` 和图标的哈希，无需重新安装。兼容 `--dry-run` 与 `--json`。 |
| `--doctor` | 执行 Arch Linux / CachyOS 环境诊断，并给出缺失的 `pacman` 软件包建议。 |
| `--json` | 向 `stdout` 输出结构化、确定性的 JSON（支持 `-l`、`--doctor`、`--verify`、`--migrate-registry`、`--dry-run`、安装和卸载）。 |
| `--generate-completion <SHELL>` | 向 `stdout` 打印适用于 `<SHELL>`（`bash`、`zsh`、`fish`、`elvish`、`powershell`）的自动补全脚本。 |
| `--generate-man` | 向 `stdout` 打印 `roff` 格式的手册页。 |
| `-h`, `--help` | 显示完整的 CLI 帮助信息。 |
| `-V`, `--version` | 显示工具版本（`0.2.1`）。 |

### 实用示例

```bash
# 在任何磁盘写入之前先校验官方 SHA-256 再安装
install-appimage --sha256 0123456789abcdef... ./Obsidian-1.7.4.AppImage

# 移动原文件并自定义名称/slug 进行安装
install-appimage --move --name "Obsidian Notes" ./Obsidian-1.7.4.AppImage

# 仅安装到桌面菜单，不在 ~/.local/bin 创建链接
install-appimage --no-cli ./MyApp.AppImage

# 模拟安装并输出 JSON 以便自动化处理
install-appimage --dry-run --json ./MyApp.AppImage

# 若目标位置已存在未追踪文件，强制覆盖
install-appimage --force ./MyApp.AppImage

# 列出受管理的 AppImage（人类可读格式或供 Rofi/Waybar 使用的 JSON）
install-appimage -l
install-appimage -l --json

# 校验所有已安装 AppImage 的 SHA-256 完整性（或对所有产物执行严格审计）
install-appimage --verify
install-appimage --verify --strict --json
install-appimage --verify obsidian --json

# 迁移旧版 registry.json（schema v1 -> v2）而无需重新安装 AppImage
install-appimage --migrate-registry --dry-run --json
install-appimage --migrate-registry --json

# 按 slug、名称或文件路径卸载
install-appimage -u obsidian
install-appimage -u "Obsidian Notes"
install-appimage -u ~/Applications/Obsidian-1.7.4.AppImage

# 模拟卸载
install-appimage -u --dry-run obsidian

# 诊断 Arch Linux / CachyOS 依赖（人类可读格式或 JSON）
install-appimage --doctor
install-appimage --doctor --json
```

---

## 环境诊断 (`--doctor`)

`install-appimage --doctor` 命令会检查以下项目：

1. 执行权限（若通过 `sudo`/root 运行会发出警告）。
2. 是否存在 `libfuse.so.2`（`fuse2`）和 `libfuse3.so.3` / `fusermount3`（`fuse3`）。
3. 是否存在 `desktop-file-validate` 和 `update-desktop-database`（`desktop-file-utils`）。
4. 是否存在 `gtk-update-icon-cache`（`gtk-update-icon-cache`）。
5. 是否存在 `kbuildsycoca6` / `kbuildsycoca5`（`kservice`，KDE Plasma 可选）。
6. `PATH` 环境变量中是否包含 `~/.local/bin`。
7. 用户 XDG 目录的写入/创建权限。

如果缺少任何软件包，该命令会打印出推荐执行的精确 `sudo pacman -S ...` 命令（并在 `--json` 模式下通过 `missing_pacman_packages` 字段返回）。

---

## 开发、模糊测试与测试

运行格式检查、严格 lint、单元/组件/集成测试及构建：

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

模糊测试目标（`cargo-fuzz` + `nightly`）及种子语料库（`fuzz/corpus/`）独立存放在 `fuzz/` 目录中：

```bash
cargo +nightly fuzz run elf
cargo +nightly fuzz run desktop_entry
cargo +nightly fuzz run svg_sanitizer
cargo +nightly fuzz run iso9660
```

---

## 许可证

基于 **MIT** 许可证分发。详情请参阅 [LICENSE](LICENSE) 文件。

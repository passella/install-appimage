# install-appimage

> 🌐 **Idiomas:** [🇧🇷 Português](README.md) | [🇺🇸 English](README.en.md) | 🇪🇸 **Español** | [🇨🇳 简体中文](README.zh-CN.md)

Gestor CLI en Rust para instalar, actualizar, verificar integridad, diagnosticar, listar y desinstalar **AppImages** en Linux (con enfoque en **Arch Linux** y **CachyOS**) utilizando integración XDG exclusivamente a nivel de usuario (**sin `sudo`**).

---

## Índice

- [Características principales](#características-principales)
- [Seguridad y modelo de extracción](#seguridad-y-modelo-de-extracción)
- [Prerrequisitos e Instalación](#prerrequisitos-e-instalación)
- [Estructura de archivos de usuario (XDG)](#estructura-de-archivos-de-usuario-xdg)
- [Guía de Uso](#guía-de-uso)
- [Diagnóstico del entorno (`--doctor`)](#diagnóstico-del-entorno---doctor)
- [Desarrollo, Fuzzing y Pruebas](#desarrollo-fuzzing-y-pruebas)
- [Licencia](#licencia)

---

## Características principales

- **Instalación a nivel de usuario sin `sudo`:** copia (por defecto) o mueve (`--move`) el archivo AppImage a `~/Applications/`, aplica permiso ejecutable (`0755`) y mantiene un symlink estable `~/Applications/<slug>.AppImage`.
- **Acceso directo en la terminal (`PATH`):** crea un symlink CLI en `~/.local/bin/<slug>` apuntando al symlink estable (desactivable con `--no-cli`).
- **Integración con el menú del sistema:** extrae iconos (`.png` en tamaños `hicolor` + `.svg` en `scalable`), normaliza `Categories=` según la especificación FreeDesktop Desktop Menu (deduplicando, eliminando `Utility` redundante junto a categorías principales específicas y garantizando `AudioVideo` cuando `Audio`/`Video` están presentes) y genera `~/.local/share/applications/<slug>.desktop`.
- **Verificación criptográfica de integridad (`--sha256` y `--verify`):** valida el checksum SHA-256 en streaming antes de cualquier escritura durante la instalación (`--sha256 <HEX>`) y audita los binarios ya instalados en `~/Applications/` contra `registry.json` (`--verify`, o `--verify --strict` para validar también el contenido SHA-256 de `.desktop` e iconos almacenados en el schema v2 del registro y la consistencia de los symlinks).
- **Migración explícita del registro v1 → v2 (`--migrate-registry`):** promueve registros `registry.json` creados en la v0.1.0 al schema v2 calculando en streaming (`O_NOFOLLOW | O_NONBLOCK`) los hashes SHA-256 del archivo `.desktop` y de los iconos ya instalados, sin necesidad de reinstalar el AppImage (soporta `--dry-run`, `--json` y es idempotente).
- **Salida JSON estructurada (`--json`):** genera salida JSON determinista en `stdout` para `-l`/`--list`, `--doctor`, `--verify`, `--migrate-registry`, `--dry-run`, instalación y desinstalación — ideal para Waybar, Rofi y scripts de automatización.
- **Autocompletado de shell y manpage (`--generate-completion` / `--generate-man`):** genera scripts nativos para `bash`, `zsh`, `fish`, `elvish` y `powershell`, además de una página de manual `roff` directamente en `stdout`.
- **Actualización limpia sin archivos huérfanos:** al instalar una nueva versión de una aplicación ya registrada, elimina automáticamente el binario antiguo y los iconos obsoletos tras completar la nueva instalación.
- **Desinstalación quirúrgica (`-u` / `--uninstall`):** acepta el nombre de la aplicación, slug o ruta/nombre del archivo `.AppImage`, eliminando únicamente los archivos rastreados dentro de los directorios XDG del usuario.
- **Simulación segura (`--dry-run`):** muestra exactamente lo que se instalaría, actualizaría o eliminaría sin modificar ningún archivo en el disco.
- **Actualización automática de cachés de escritorio:** ejecuta `desktop-file-validate`, `update-desktop-database`, `gtk-update-icon-cache` y `kbuildsycoca6`/`kbuildsycoca5` cuando están presentes en el host (con degradación elegante si alguno falta).
- **Diagnóstico del sistema (`--doctor`):** verifica FUSE 2/3, herramientas XDG, `PATH` y directorios locales, sugiriendo los paquetes exactos de `pacman` cuando falta algún componente.

---

## Seguridad y modelo de extracción

- **Cero ejecución de binarios no confiables durante la instalación:**
  - **AppImage Type 2 (ELF + SquashFS):** el desplazamiento posterior al ELF se calcula mediante un parser ELF en Rust puro y solo los metadados necesarios (`.desktop`, `.DirIcon` e iconos) se leen directamente del SquashFS (`gzip`, `xz`, `zstd`, `lz4`) sin ejecutar jamás el binario AppImage (no se invoca `--appimage-extract`).
  - **AppImage Type 1 (ISO9660):** parser ISO9660 nativo en Rust puro, sin dependencias y sin `unsafe` (ECMA-119 PVD + Rock Ridge `NM`/`SL`/`PX`/`CE`/`CL`/`RE` + respaldo Joliet SVD), sin subprocesos externos (`bsdtar` no es necesario) y con límites estrictos (*hard budgets*) contra bucles de directorios/extents, traversal y symlinks que escapen de la raíz.
  - **Fail-closed:** los payloads que no pueden leerse estáticamente (como DwarFS) se rechazan de forma segura sin ejecutar código ELF.
- **Protección contra path traversal, escape de symlinks, TOCTOU y código inseguro (`#![forbid(unsafe_code)]`):** compilación con prohibición estricta de `unsafe`, validación de componentes de ruta, rechazo de escapes `..`, bytes `NUL`, caracteres BiDi/Tags Unicode, apertura mediante `O_NOFOLLOW | O_NONBLOCK` sin seguir symlinks ni bloquear en FIFOs en origen/registro/verificación, comprobación `--sha256` en streaming previa a la instalación, verificación SHA-256 durante el staging, bloqueo de directorios symlink bajo raíces XDG, validación estricta del schema v2 (con lectura retrocompatible v1) e integridad de rutas/hashes en `registry.json`, además de gobernanza de dependencias mediante `deny.toml` (`cargo-deny`) + `cargo-audit` en CI.
- **Saneamiento de `.desktop` y anti-inyección de comandos:**
  - Exige `Type=Application` obligatorio y rechaza bloques `[Desktop Entry]` duplicados, grupos `[Desktop Action ...]`, `DBusActivatable` y `Path=`.
  - Elimina secuencias ANSI (`CSI`/`OSC`/`DCS`/`APC`), caracteres de control y caracteres BiDi de los campos textuales, JSON y salidas de terminal.
  - Sustituye íntegramente el comando original de `Exec=` por la ruta escapada del symlink estable (con composición completa Layer 1 + Layer 2 compatible con `GLib.KeyFile` / `desktop-file-validate`), preservando como máximo un único *field code* XDG de la lista blanca (`%f`, `%F`, `%u` o `%U`).
  - Valida iconos SVG con un parser XML estructural en lista blanca estricta (rechaza `<!DOCTYPE>`/`<!ENTITY>` XXE, instrucciones de procesamiento como `<?xml-stylesheet?>`, `xi:include`, `<script>`, `<foreignObject>`, atributos `on*`, SMIL que mute `href`/`on*`, y cualquier URI externa/activa o CSS `url()`/`@import` no local).
- **Escrituras atómicas y protección contra colisiones:** utiliza archivos temporales y `rename` atómico en el mismo directorio; rechaza sobrescribir archivos no gestionados sin `--force` y bloquea colisiones con archivos pertenecientes a otra aplicación gestionada.

---

## Prerrequisitos e Instalación

### Prerrequisitos (Arch Linux / CachyOS)

Para ejecutar AppImages y actualizar las cachés del entorno gráfico:

```bash
sudo pacman -S fuse2 fuse3 desktop-file-utils gtk-update-icon-cache
```

Opcional según el entorno:
- `kservice` (`kbuildsycoca6`) para actualizar la caché de menús de KDE Plasma.

### Instalación rápida mediante GitHub Release (`install.sh`)

El script `install.sh` detecta automáticamente la arquitectura (`x86_64` / `aarch64`), descarga el tarball estático (`musl`) desde GitHub Releases, valida obligatoriamente el checksum mediante `SHA256SUMS.txt` e instala el binario, los scripts de autocompletado (`bash`, `zsh`, `fish`) y la página de manual a nivel de usuario (`~/.local`):

```bash
curl -fsSL https://raw.githubusercontent.com/passella/install-appimage/master/install.sh | bash -s -- --repo passella/install-appimage --release
```

Opciones principales de `install.sh`:
- `--release`: descarga el binario precompilado desde GitHub Releases (predeterminado fuera del repositorio; usa `--version <vX.Y.Z>` para fijar una etiqueta, `--repo <OWNER/REPO>` / `INSTALL_APPIMAGE_REPO`, o `INSTALL_APPIMAGE_RELEASE_BASE_URL` para espejos o pruebas locales).
- `--source`: compila localmente mediante `cargo build --release --locked` (predeterminado cuando se ejecuta dentro del repositorio).
- `--bin <PATH>`: instala un binario local ya compilado.
- `--system`: instala globalmente en `/usr/local` (usa `sudo` solo cuando es necesario).
- `--prefix <DIR>`: instala en un prefijo personalizado (`<DIR>/bin`, `<DIR>/share`).
- `--no-completions` / `--no-man`: omite la instalación del autocompletado o de la página de manual.
- `--dry-run`: muestra todas las acciones planificadas sin modificar el sistema de archivos.

### Compilación e instalación desde el código fuente

Requiere toolchain Rust compatible con **Rust Edition 2024**:

```bash
git clone https://github.com/passella/install-appimage.git
cd install-appimage
./install.sh
```

O directamente mediante Cargo (sin autocompletado ni página de manual automáticos):

```bash
cargo install --path .
```

Asegúrate de que `~/.local/bin` (o `~/.cargo/bin`) esté en tu `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Desinstalación de la CLI (`uninstall.sh`)

Para eliminar el binario, los scripts de autocompletado y la página de manual instalados por `install.sh`:

```bash
./uninstall.sh
```

Opciones soportadas: `--system`, `--prefix <DIR>` y `--dry-run`.

> **Nota:** `uninstall.sh` solo elimina la CLI `install-appimage`, sus scripts de autocompletado y su página de manual. Tus AppImages gestionados en `~/Applications/` y el registro `~/.local/share/install-appimage/registry.json` permanecen **preservados** (para eliminar un AppImage específico antes, usa `install-appimage -u <app>`).

---

## Estructura de archivos de usuario (XDG)

| Artefacto | Ubicación predeterminada (respeta `XDG_DATA_HOME`) |
| --- | --- |
| Binario AppImage (`chmod 755`) | `~/Applications/<archivo>.AppImage` |
| Symlink estable | `~/Applications/<slug>.AppImage` *(omitido cuando el archivo ya tiene exactamente ese nombre)* |
| Acceso directo CLI en `PATH` | `~/.local/bin/<slug>` *(omitido con `--no-cli`)* |
| Entrada desktop | `~/.local/share/applications/<slug>.desktop` |
| Iconos (`png` / `svg`) | `~/.local/share/icons/hicolor/<size>/apps/<slug>.<ext>` o `scalable/apps/<slug>.svg` |
| Registro de estado | `~/.local/share/install-appimage/registry.json` |

---

## Guía de Uso

### Sintaxis

```text
install-appimage [OPCIONES] [APPIMAGE]
```

### Opciones y Flags

| Opción | Descripción |
| --- | --- |
| `<APPIMAGE>` | Ruta al archivo `.AppImage` a instalar/actualizar (o nombre, slug o ruta del archivo cuando se usa con `-u`/`--uninstall` o `--verify`). |
| `--move` | Mueve el archivo `.AppImage` a `~/Applications/` en lugar de copiarlo. |
| `--name <NAME>` | Sobrescribe el nombre visible de la aplicación y el `<slug>` derivado. |
| `--no-cli` | No crea el symlink de terminal en `~/.local/bin/<slug>`. |
| `--force` | Fuerza la sobrescritura de un archivo o symlink no gestionado que ya exista en el destino. |
| `--sha256 <HEX>` | Valida el hash SHA-256 esperado (64 dígitos hexadecimales) en streaming antes de instalar o simular. |
| `--dry-run` | Simula todas las operaciones de instalación o desinstalación sin modificar el sistema de archivos. |
| `-u`, `--uninstall` | Desinstala un AppImage gestionado (indica el nombre, slug o ruta/nombre del archivo `.AppImage` en `<APPIMAGE>`). |
| `-l`, `--list` | Lista los AppImages instalados y gestionados por `install-appimage`. |
| `--verify` | Verifica la integridad SHA-256 y la seguridad de rutas de los AppImages instalados (o de una app específica) contra `registry.json`. Devuelve un código de salida distinto de cero ante discrepancias. |
| `--strict` | Usado con `--verify`: valida también la integridad SHA-256 (schema v2) y la contención de `.desktop`, iconos y symlinks estable/CLI contra `registry.json`. |
| `--migrate-registry` | Promueve `registry.json` del schema v1 al v2 calculando en streaming (`O_NOFOLLOW \| O_NONBLOCK`) los hashes de `.desktop` e iconos existentes, sin reinstalar. Compatible con `--dry-run` y `--json`. |
| `--doctor` | Ejecuta el diagnóstico del entorno Arch Linux / CachyOS y sugiere paquetes `pacman` faltantes. |
| `--json` | Emite salida JSON estructurada y determinista en `stdout` (`-l`, `--doctor`, `--verify`, `--migrate-registry`, `--dry-run`, instalación y desinstalación). |
| `--generate-completion <SHELL>` | Imprime el script de autocompletado para `<SHELL>` (`bash`, `zsh`, `fish`, `elvish`, `powershell`) en `stdout`. |
| `--generate-man` | Imprime la página de manual en formato `roff` en `stdout`. |
| `-h`, `--help` | Muestra la ayuda completa de la CLI. |
| `-V`, `--version` | Muestra la versión de la herramienta (`0.2.0`). |

### Ejemplos prácticos

```bash
# Instalar verificando el SHA-256 oficial antes de cualquier escritura
install-appimage --sha256 0123456789abcdef... ./Obsidian-1.7.4.AppImage

# Instalar moviendo el archivo original y personalizando el nombre/slug
install-appimage --move --name "Obsidian Notes" ./Obsidian-1.7.4.AppImage

# Instalar solo en el menú desktop, sin enlace en ~/.local/bin
install-appimage --no-cli ./MyApp.AppImage

# Simular instalación con salida JSON para automatización
install-appimage --dry-run --json ./MyApp.AppImage

# Forzar sobrescritura si ya existe un archivo no rastreado en el destino
install-appimage --force ./MyApp.AppImage

# Listar AppImages gestionados (legible o JSON para Rofi/Waybar)
install-appimage -l
install-appimage -l --json

# Verificar integridad SHA-256 de todos los AppImages instalados (o auditoría estricta de todos los artefactos)
install-appimage --verify
install-appimage --verify --strict --json
install-appimage --verify obsidian --json

# Migrar registry.json legado (schema v1 -> v2) sin reinstalar los AppImages
install-appimage --migrate-registry --dry-run --json
install-appimage --migrate-registry --json

# Desinstalar por slug, nombre o ruta del archivo
install-appimage -u obsidian
install-appimage -u "Obsidian Notes"
install-appimage -u ~/Applications/Obsidian-1.7.4.AppImage

# Simular desinstalación
install-appimage -u --dry-run obsidian

# Diagnosticar dependencias en Arch Linux / CachyOS (legible o JSON)
install-appimage --doctor
install-appimage --doctor --json
```

---

## Diagnóstico del entorno (`--doctor`)

El comando `install-appimage --doctor` verifica:

1. Privilegios de ejecución (advierte si se ejecuta mediante `sudo`/root).
2. Presencia de `libfuse.so.2` (`fuse2`) y `libfuse3.so.3` / `fusermount3` (`fuse3`).
3. Presencia de `desktop-file-validate` y `update-desktop-database` (`desktop-file-utils`).
4. Presencia de `gtk-update-icon-cache` (`gtk-update-icon-cache`).
5. Presencia de `kbuildsycoca6` / `kbuildsycoca5` (`kservice`, opcional para KDE Plasma).
6. Inclusión de `~/.local/bin` en la variable `PATH`.
7. Permiso de escritura/creación de los directorios XDG del usuario.

Si falta algún paquete, el comando imprime exactamente el comando `sudo pacman -S ...` recomendado (y expone `missing_pacman_packages` en modo `--json`).

---

## Desarrollo, Fuzzing y Pruebas

Ejecuta formato, lint estricto, pruebas unitarias/de componente/de integración y compilación:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Los targets de fuzzing (`cargo-fuzz` + `nightly`) y el corpus semilla (`fuzz/corpus/`) están aislados en `fuzz/`:

```bash
cargo +nightly fuzz run elf
cargo +nightly fuzz run desktop_entry
cargo +nightly fuzz run svg_sanitizer
cargo +nightly fuzz run iso9660
```

---

## Licencia

Distribuido bajo la licencia **MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

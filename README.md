# install-appimage

> 🌐 **Idiomas:** 🇧🇷 **Português** | [🇺🇸 English](README.en.md) | [🇪🇸 Español](README.es.md) | [🇨🇳 简体中文](README.zh-CN.md)

Gerenciador CLI em Rust para instalar, atualizar, verificar integridade, diagnosticar, listar e desinstalar **AppImages** no Linux (com foco em **Arch Linux** e **CachyOS**) utilizando integração XDG exclusivamente em nível de usuário (**sem `sudo`**).

---

## Sumário

- [Recursos principais](#recursos-principais)
- [Segurança e modelo de extração](#segurança-e-modelo-de-extração)
- [Pré-requisitos e Instalação](#pré-requisitos-e-instalação)
- [Layout de arquivos no usuário (XDG)](#layout-de-arquivos-no-usuário-xdg)
- [Guia de Uso](#guia-de-uso)
- [Diagnóstico de ambiente (`--doctor`)](#diagnóstico-de-ambiente---doctor)
- [Desenvolvimento, Fuzzing e Testes](#desenvolvimento-fuzzing-e-testes)
- [Licença](#licença)

---

## Recursos principais

- **Instalação user-level sem `sudo`:** copia (padrão) ou move (`--move`) o arquivo AppImage para `~/Applications/`, aplica permissão executável (`0755`) e mantém um symlink estável `~/Applications/<slug>.AppImage`.
- **Atalho no terminal (`PATH`):** cria um symlink CLI em `~/.local/bin/<slug>` apontando para o symlink estável (desativável com `--no-cli`).
- **Integração com o menu do sistema:** extrai ícones (`.png` em tamanhos `hicolor` + `.svg` em `scalable`), normaliza `Categories=` segundo a especificação FreeDesktop Desktop Menu (deduplicando, removendo `Utility` redundante junto a categorias principais específicas e garantindo `AudioVideo` quando `Audio`/`Video` estão presentes) e gera `~/.local/share/applications/<slug>.desktop`.
- **Verificação criptográfica de integridade (`--sha256` e `--verify`):** valida o checksum SHA-256 em streaming antes de qualquer escrita durante a instalação (`--sha256 <HEX>`) e audita os binários já instalados em `~/Applications/` contra `registry.json` (`--verify`, ou `--verify --strict` para validar também conteúdo SHA-256 de `.desktop` e ícones armazenados no schema v2 do registro e consistência dos symlinks).
- **Migração explícita do registro v1 → v2 (`--migrate-registry`):** promove registros `registry.json` criados na v0.1.0 para o schema v2 calculando em streaming (`O_NOFOLLOW | O_NONBLOCK`) os hashes SHA-256 do `.desktop` e dos ícones já instalados, sem precisar reinstalar o AppImage (suporta `--dry-run`, `--json` e é idempotente).
- **Saída JSON estruturada (`--json`):** gera saída JSON determinística em `stdout` para `-l`/`--list`, `--doctor`, `--verify`, `--migrate-registry`, `--dry-run`, instalação e desinstalação — ideal para Waybar, Rofi e scripts de automação.
- **Autocompletar de shell e manpage (`--generate-completion` / `--generate-man`):** gera scripts nativos para `bash`, `zsh`, `fish`, `elvish` e `powershell`, além de página de manual `roff` diretamente em `stdout`.
- **Atualização limpa sem arquivos órfãos:** ao instalar uma nova versão de um app já registrado, remove o binário antigo e ícones obsoletos automaticamente após concluir a nova instalação.
- **Desinstalação cirúrgica (`-u` / `--uninstall`):** aceita nome do app, slug ou caminho/nome do arquivo `.AppImage`, removendo apenas os arquivos rastreados dentro dos diretórios XDG do usuário.
- **Simulação segura (`--dry-run`):** mostra exatamente o que seria instalado, atualizado ou removido sem alterar nenhum arquivo no disco.
- **Atualização automática de caches desktop:** executa `desktop-file-validate`, `update-desktop-database`, `gtk-update-icon-cache` e `kbuildsycoca6`/`kbuildsycoca5` quando presentes no host (com degradação graciosa caso algum esteja ausente).
- **Diagnóstico de sistema (`--doctor`):** verifica FUSE 2/3, ferramentas XDG, `PATH` e diretórios locais, sugerindo os pacotes exatos do `pacman` quando algo estiver faltando.

---

## Segurança e modelo de extração

- **Zero execução de binário não confiável na instalação:**
  - **AppImage Type 2 (ELF + SquashFS):** o offset pós-ELF é calculado via parser ELF em Rust puro e apenas os metadados necessários (`.desktop`, `.DirIcon` e ícones) são lidos diretamente do SquashFS (`gzip`, `xz`, `zstd`, `lz4`) sem jamais executar o binário AppImage (`--appimage-extract` não é invocado).
  - **AppImage Type 1 (ISO9660):** parser ISO9660 nativo em Rust puro, zero-dependência e sem `unsafe` (ECMA-119 PVD + Rock Ridge `NM`/`SL`/`PX`/`CE`/`CL`/`RE` + fallback Joliet SVD), sem subprocesso externo (`bsdtar` não é necessário) e com hard budgets contra loops de diretórios/extents, traversal e symlinks escapando da raiz.
  - **Fail-closed:** payloads não legíveis estaticamente (como DwarFS) são recusados de forma segura sem executar código ELF.
- **Proteção contra path traversal, symlink escape, TOCTOU e código inseguro (`#![forbid(unsafe_code)]`):** compilação com proibição estrita de `unsafe`, validação de componentes de caminho, rejeição de escapes `..`, bytes `NUL`, caracteres BiDi/Tags Unicode, abertura via `O_NOFOLLOW | O_NONBLOCK` sem seguir symlinks nem bloquear em FIFOs na origem/registro/verificação, checagem `--sha256` em streaming pré-instalação, verificação de SHA-256 durante o staging, bloqueio de diretórios symlink sob raízes XDG, validação estrita de schema v2 (com leitura retrocompatível v1) e integridade de caminhos/hashes em `registry.json` e governança de dependências via `deny.toml` (`cargo-deny`) + `cargo-audit` no CI.
- **Sanitização de `.desktop` e anti-command-injection:**
  - Exige `Type=Application` obrigatório e rejeita blocos `[Desktop Entry]` duplicados, grupos `[Desktop Action ...]`, `DBusActivatable` e `Path=`.
  - Remove sequências ANSI (`CSI`/`OSC`/`DCS`/`APC`), controles e caracteres BiDi dos campos textuais, JSON e saídas de terminal.
  - Substitui integralmente o comando original de `Exec=` pelo caminho escapado do symlink estável (com composição completa Layer 1 + Layer 2 compatível com `GLib.KeyFile` / `desktop-file-validate`), preservando no máximo um único *field code* XDG da allowlist (`%f`, `%F`, `%u` ou `%U`).
  - Valida ícones SVG com parser XML estrutural em allowlist estrita (rejeita `<!DOCTYPE>`/`<!ENTITY>` XXE, PIs como `<?xml-stylesheet?>`, `xi:include`, `<script>`, `<foreignObject>`, atributos `on*`, SMIL mutando `href`/`on*`, e qualquer URI externa/ativa ou CSS `url()`/`@import` não-local).
- **Escritas atômicas e proteção contra colisões:** utiliza arquivos temporários e `rename` atômico no mesmo diretório; recusa sobrescrever arquivos não gerenciados sem `--force` e bloqueia colisão com arquivos pertencentes a outro aplicativo gerenciado.

---

## Pré-requisitos e Instalação

### Pré-requisitos (Arch Linux / CachyOS)

Para executar AppImages e atualizar os caches do ambiente gráfico:

```bash
sudo pacman -S fuse2 fuse3 desktop-file-utils gtk-update-icon-cache
```

Opcional conforme o ambiente:
- `kservice` (`kbuildsycoca6`) para atualizar o cache de menus do KDE Plasma.

### Instalação rápida via GitHub Release (`install.sh`)

O script `install.sh` detecta automaticamente a arquitetura (`x86_64` / `aarch64`), baixa o tarball estático (`musl`) do GitHub Releases, valida obrigatoriamente o checksum via `SHA256SUMS.txt` e instala o binário, completions (`bash`, `zsh`, `fish`) e manpage em nível de usuário (`~/.local`):

```bash
curl -fsSL https://raw.githubusercontent.com/passella/install-appimage/master/install.sh | bash -s -- --repo passella/install-appimage --release
```

Opções principais do `install.sh`:
- `--release`: baixa o binário pré-compilado do GitHub Releases (padrão fora do repositório; usa `--version <vX.Y.Z>` para fixar uma tag, `--repo <OWNER/REPO>` / `INSTALL_APPIMAGE_REPO`, ou `INSTALL_APPIMAGE_RELEASE_BASE_URL` para espelhos/testes locais).
- `--source`: compila localmente via `cargo build --release --locked` (padrão quando executado dentro do repositório).
- `--bin <PATH>`: instala um binário local já compilado.
- `--system`: instala globalmente em `/usr/local` (usa `sudo` apenas quando necessário).
- `--prefix <DIR>`: instala em um prefixo personalizado (`<DIR>/bin`, `<DIR>/share`).
- `--no-completions` / `--no-man`: omite a instalação de autocompletar ou da página de manual.
- `--dry-run`: exibe todas as ações planejadas sem modificar o sistema de arquivos.

### Compilação e instalação a partir do código-fonte

Requer toolchain Rust com suporte à **Rust Edition 2024**:

```bash
git clone https://github.com/passella/install-appimage.git
cd install-appimage
./install.sh
```

Ou diretamente via Cargo (sem completions/manpage automáticos):

```bash
cargo install --path .
```

Garanta que `~/.local/bin` (ou `~/.cargo/bin`) esteja no seu `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Desinstalação da CLI (`uninstall.sh`)

Para remover o binário, completions e manpage instalados pelo `install.sh`:

```bash
./uninstall.sh
```

Opções suportadas: `--system`, `--prefix <DIR>` e `--dry-run`.

> **Nota:** o `uninstall.sh` remove apenas a CLI `install-appimage`, suas completions e sua manpage. Seus AppImages gerenciados em `~/Applications/` e o registro `~/.local/share/install-appimage/registry.json` permanecem **preservados** (para remover um AppImage específico antes, use `install-appimage -u <app>`).

---

## Layout de arquivos no usuário (XDG)

| Artefato | Local padrão (respeita `XDG_DATA_HOME`) |
| --- | --- |
| Binário AppImage (`chmod 755`) | `~/Applications/<arquivo>.AppImage` |
| Symlink estável | `~/Applications/<slug>.AppImage` *(omitido quando o arquivo já possui exatamente esse nome)* |
| Atalho CLI no `PATH` | `~/.local/bin/<slug>` *(omitido com `--no-cli`)* |
| Entrada desktop | `~/.local/share/applications/<slug>.desktop` |
| Ícones (`png` / `svg`) | `~/.local/share/icons/hicolor/<size>/apps/<slug>.<ext>` ou `scalable/apps/<slug>.svg` |
| Registro de estado | `~/.local/share/install-appimage/registry.json` |

---

## Guia de Uso

### Sintaxe

```text
install-appimage [OPÇÕES] [APPIMAGE]
```

### Opções e Flags

| Opção | Descrição |
| --- | --- |
| `<APPIMAGE>` | Caminho para o arquivo `.AppImage` a instalar/atualizar (ou nome, slug ou caminho do arquivo quando usado com `-u`/`--uninstall` ou `--verify`). |
| `--move` | Move o arquivo `.AppImage` para `~/Applications/` em vez de copiá-lo. |
| `--name <NAME>` | Sobrescreve o nome de exibição do app e o `<slug>` derivado. |
| `--no-cli` | Não cria o symlink de terminal em `~/.local/bin/<slug>`. |
| `--force` | Força sobrescrita de arquivo ou symlink não gerenciado já existente no destino. |
| `--sha256 <HEX>` | Valida o hash SHA-256 esperado (64 dígitos hexadecimais) em streaming antes de instalar/simular. |
| `--dry-run` | Simula todas as operações de instalação ou desinstalação sem modificar o sistema de arquivos. |
| `-u`, `--uninstall` | Desinstala um AppImage gerenciado (informe o nome, slug ou caminho/nome do arquivo `.AppImage` em `<APPIMAGE>`). |
| `-l`, `--list` | Lista os AppImages instalados e gerenciados pelo `install-appimage`. |
| `--verify` | Verifica a integridade SHA-256 e a segurança de caminho dos AppImages instalados (ou de um app específico) contra `registry.json`. Retorna exit code não-zero em divergências. |
| `--strict` | Usado com `--verify`: valida também integridade SHA-256 (schema v2) e contenção de `.desktop`, ícones e symlinks estável/CLI contra `registry.json`. |
| `--migrate-registry` | Promove `registry.json` do schema v1 para v2 calculando em streaming (`O_NOFOLLOW \| O_NONBLOCK`) os hashes de `.desktop` e ícones existentes, sem reinstalar. Compatível com `--dry-run` e `--json`. |
| `--doctor` | Executa diagnóstico do ambiente Arch Linux / CachyOS e sugere pacotes `pacman` ausentes. |
| `--json` | Emite saída JSON estruturada e determinística em `stdout` (`-l`, `--doctor`, `--verify`, `--migrate-registry`, `--dry-run`, instalação e desinstalação). |
| `--generate-completion <SHELL>` | Imprime o script de autocompletar para `<SHELL>` (`bash`, `zsh`, `fish`, `elvish`, `powershell`) em `stdout`. |
| `--generate-man` | Imprime a página de manual em formato `roff` em `stdout`. |
| `-h`, `--help` | Exibe a ajuda completa da CLI. |
| `-V`, `--version` | Exibe a versão da ferramenta (`0.2.0`). |

### Exemplos práticos

```bash
# Instalar verificando o SHA-256 oficial antes de qualquer escrita
install-appimage --sha256 0123456789abcdef... ./Obsidian-1.7.4.AppImage

# Instalar movendo o arquivo original e personalizando o nome/slug
install-appimage --move --name "Obsidian Notes" ./Obsidian-1.7.4.AppImage

# Instalar apenas no menu desktop, sem link em ~/.local/bin
install-appimage --no-cli ./MyApp.AppImage

# Simular instalação com saída JSON para automação
install-appimage --dry-run --json ./MyApp.AppImage

# Forçar sobrescrita se já existir arquivo não rastreado no destino
install-appimage --force ./MyApp.AppImage

# Listar AppImages gerenciados (humano ou JSON para Rofi/Waybar)
install-appimage -l
install-appimage -l --json

# Verificar integridade SHA-256 de todos os AppImages instalados (ou auditoria estrita de todos os artefatos)
install-appimage --verify
install-appimage --verify --strict --json
install-appimage --verify obsidian --json

# Migrar registry.json legado (schema v1 -> v2) sem reinstalar os AppImages
install-appimage --migrate-registry --dry-run --json
install-appimage --migrate-registry --json

# Desinstalar por slug, nome ou caminho do arquivo
install-appimage -u obsidian
install-appimage -u "Obsidian Notes"
install-appimage -u ~/Applications/Obsidian-1.7.4.AppImage

# Simular desinstalação
install-appimage -u --dry-run obsidian

# Diagnosticar dependências no Arch Linux / CachyOS (humano ou JSON)
install-appimage --doctor
install-appimage --doctor --json
```

---

## Diagnóstico de ambiente (`--doctor`)

O comando `install-appimage --doctor` verifica:

1. Privilégio de execução (alerta caso executado via `sudo`/root).
2. Presença de `libfuse.so.2` (`fuse2`) e `libfuse3.so.3` / `fusermount3` (`fuse3`).
3. Presença de `desktop-file-validate` e `update-desktop-database` (`desktop-file-utils`).
4. Presença de `gtk-update-icon-cache` (`gtk-update-icon-cache`).
5. Presença de `kbuildsycoca6` / `kbuildsycoca5` (`kservice`, opcional para KDE Plasma).
6. Inclusão de `~/.local/bin` na variável `PATH`.
7. Permissão de escrita/criação dos diretórios XDG do usuário.

Caso falte algum pacote, o comando imprime exatamente o comando `sudo pacman -S ...` recomendado (e expõe `missing_pacman_packages` no modo `--json`).

---

## Desenvolvimento, Fuzzing e Testes

Execute formatação, lint estrito, testes unitários/componente/integração e build:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

Targets de fuzzing (`cargo-fuzz` + `nightly`) e corpus semente (`fuzz/corpus/`) ficam isolados em `fuzz/`:

```bash
cargo +nightly fuzz run elf
cargo +nightly fuzz run desktop_entry
cargo +nightly fuzz run svg_sanitizer
cargo +nightly fuzz run iso9660
```

---

## Licença

Distribuído sob a licença **MIT**. Consulte o arquivo [LICENSE](LICENSE) para mais detalhes.

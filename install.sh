#!/usr/bin/env bash
set -euo pipefail

readonly APP_NAME="install-appimage"
readonly DEFAULT_BIN_NAME="install-appimage"

MODE=""
SCOPE="user"
PREFIX=""
VERSION=""
REPO="${INSTALL_APPIMAGE_REPO:-}"
RELEASE_BASE_URL="${INSTALL_APPIMAGE_RELEASE_BASE_URL:-}"
BIN_PATH=""
INSTALL_COMPLETIONS=1
INSTALL_MAN=1
DRY_RUN=0
TMP_DIR=""

usage() {
  cat <<'EOF'
Usage: install.sh [OPTIONS]

Install install-appimage, shell completions (bash, zsh, fish), and manpage.

Modes (mutually exclusive; auto-detected when omitted):
  --source              Build and install from local Cargo checkout
  --release             Download prebuilt static musl binary from GitHub Releases
  --bin <PATH>          Install an existing local binary

Scope (default: user-level XDG paths):
  --system              Install system-wide under /usr/local (uses sudo if needed)
  --prefix <DIR>        Install under custom prefix <DIR> (bin/, share/)

Release options:
  --version <vX.Y.Z>    Release tag to download (default: latest)
  --repo <OWNER/REPO>   GitHub repository (or set INSTALL_APPIMAGE_REPO)

Extras:
  --no-completions      Skip shell completions (bash, zsh, fish)
  --no-man              Skip manpage (install-appimage.1.gz)
  --dry-run             Show planned actions without modifying the filesystem
  -h, --help            Show this help message

Default user-level paths:
  Binary:      ~/.local/bin/install-appimage
  Completions: ${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions/install-appimage
               ${XDG_DATA_HOME:-~/.local/share}/zsh/site-functions/_install-appimage
               ${XDG_DATA_HOME:-~/.local/share}/fish/vendor_completions.d/install-appimage.fish
  Manpage:     ${XDG_DATA_HOME:-~/.local/share}/man/man1/install-appimage.1.gz
EOF
}

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'Warning: %s\n' "$*" >&2
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
    rm -rf -- "${TMP_DIR}"
  fi
}

trap cleanup EXIT

require_cmd() {
  local cmd="$1"
  command -v "${cmd}" >/dev/null 2>&1 || die "Required command not found: ${cmd}"
}

validate_no_ctrl() {
  local label="$1"
  local val="$2"
  if [[ -z "${val}" ]]; then
    die "${label} cannot be empty."
  fi
  if [[ "${val}" =~ [[:cntrl:]] ]]; then
    die "${label} contains invalid control characters."
  fi
}

normalize_and_validate_prefix() {
  local raw="$1"
  validate_no_ctrl "Prefix" "${raw}"
  while [[ "${raw}" == */ ]]; do
    raw="${raw%/}"
  done
  if [[ -z "${raw}" ]]; then
    die "Invalid prefix '/': root directory cannot be used as --prefix."
  fi
  if [[ "${raw}" =~ (^|/)\.\.(/|$) ]]; then
    die "Invalid prefix '${1}': '..' path segments are not allowed."
  fi
  while [[ "${raw}" == *//* ]]; do
    raw="${raw//\/\//\/}"
  done
  printf '%s\n' "${raw}"
}

validate_repo() {
  local repo="$1"
  validate_no_ctrl "Repository" "${repo}"
  if [[ ! "${repo}" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    die "Invalid repository '${repo}'. Expected format: OWNER/REPO"
  fi
  local owner="${repo%%/*}"
  local name="${repo#*/}"
  if [[ "${owner}" == "." || "${owner}" == ".." || "${name}" == "." || "${name}" == ".." ]]; then
    die "Invalid repository '${repo}'."
  fi
}

validate_tag() {
  local tag="$1"
  validate_no_ctrl "Version tag" "${tag}"
  if [[ ! "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
    die "Invalid version tag '${tag}'. Expected format: vX.Y.Z"
  fi
}

validate_release_base_url() {
  local raw="$1"
  validate_no_ctrl "INSTALL_APPIMAGE_RELEASE_BASE_URL" "${raw}"
  if [[ "${raw}" =~ [[:space:]] ]]; then
    die "INSTALL_APPIMAGE_RELEASE_BASE_URL cannot contain whitespace."
  fi
  while [[ "${raw}" == */ ]]; do
    raw="${raw%/}"
  done
  if [[ "${raw}" =~ ^https://([A-Za-z0-9._-]+|\[[0-9A-Fa-f:]+\])(:[0-9]+)?(/[^?#]*)?$ ]]; then
    printf '%s\n' "${raw}"
    return 0
  fi
  if [[ "${raw}" =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/[^?#]*)?$ ]]; then
    printf '%s\n' "${raw}"
    return 0
  fi
  die "Invalid INSTALL_APPIMAGE_RELEASE_BASE_URL '${1}'. Only https:// URLs or loopback http:// (127.0.0.1, localhost, [::1]) are allowed."
}

is_loopback_http_url() {
  local url="$1"
  [[ "${url}" =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/.*)?$ ]]
}

detect_script_dir() {
  local src="${BASH_SOURCE[0]:-}"
  if [[ -n "${src}" && -f "${src}" ]]; then
    cd -- "$(dirname -- "${src}")" && pwd -P
  fi
}

is_local_checkout() {
  local dir="$1"
  [[ -n "${dir}" && -f "${dir}/Cargo.toml" && -d "${dir}/src" ]] &&
    grep -qE '^name[[:space:]]*=[[:space:]]*"install-appimage"' "${dir}/Cargo.toml"
}

detect_repo_from_git() {
  local search_dir="$1"
  local remote_url=""
  command -v git >/dev/null 2>&1 || return 1

  if [[ -n "${search_dir}" && -d "${search_dir}" ]]; then
    remote_url="$(git -C "${search_dir}" remote get-url origin 2>/dev/null || true)"
  else
    remote_url="$(git remote get-url origin 2>/dev/null || true)"
  fi

  [[ -n "${remote_url}" ]] || return 1

  remote_url="${remote_url%/}"
  remote_url="${remote_url%.git}"

  if [[ "${remote_url}" =~ ^https?://github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${remote_url}" =~ ^ssh://git@github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${remote_url}" =~ ^git://github\.com/([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "${remote_url}" =~ ^git@github\.com:([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi

  return 1
}

detect_target_triple() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  if [[ "${os}" != "Linux" ]]; then
    die "Unsupported OS '${os}'. install-appimage supports Linux only."
  fi

  case "${arch}" in
    x86_64|amd64)
      printf '%s\n' "x86_64-unknown-linux-musl"
      ;;
    aarch64|arm64)
      printf '%s\n' "aarch64-unknown-linux-musl"
      ;;
    *)
      die "Unsupported architecture '${arch}'. Use --source to compile locally."
      ;;
  esac
}

http_download() {
  local url="$1"
  local dest="$2"

  if is_loopback_http_url "${url}"; then
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --proto '=http' --proto-redir '=http' --max-redirs 0 --retry 3 -o "${dest}" -- "${url}"
    elif command -v wget >/dev/null 2>&1; then
      wget -q --max-redirect=0 -O "${dest}" -- "${url}"
    else
      die "Neither curl nor wget is available for downloading."
    fi
  else
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 -o "${dest}" -- "${url}"
    elif command -v wget >/dev/null 2>&1; then
      wget -q --https-only -O "${dest}" -- "${url}"
    else
      die "Neither curl nor wget is available for downloading."
    fi
  fi
}

resolve_latest_tag() {
  local base_url="$1"
  local latest_url="${base_url}/latest"
  local effective_url=""
  local status_line=""
  local status_code=""
  local redirect_url=""
  local tag=""

  if command -v curl >/dev/null 2>&1; then
    local -a proto_args=(--proto '=https' --proto-redir '=https' --tlsv1.2)
    if is_loopback_http_url "${latest_url}"; then
      proto_args=(--proto '=http' --proto-redir '=http')
    fi

    effective_url="$(curl -fsSL "${proto_args[@]}" --retry 3 -o /dev/null -w '%{url_effective}' -- "${latest_url}" 2>/dev/null || true)"
    if [[ ! "${effective_url}" =~ /tag/([^/?#]+)$ ]]; then
      status_line="$(curl -sS "${proto_args[@]}" --retry 3 -o /dev/null -w '%{http_code} %{redirect_url}' -- "${latest_url}" 2>/dev/null || true)"
      status_code="${status_line%% *}"
      redirect_url="${status_line#* }"
      case "${status_code}" in
        301|302|303|307|308)
          effective_url="${redirect_url}"
          ;;
      esac
    fi
    [[ -n "${effective_url}" ]] || die "Failed to query latest release at '${latest_url}'."
  elif command -v wget >/dev/null 2>&1; then
    local -a wget_args=(--https-only --max-redirect=0 --spider --server-response)
    if is_loopback_http_url "${latest_url}"; then
      wget_args=(--max-redirect=0 --spider --server-response)
    fi
    effective_url="$(wget "${wget_args[@]}" -- "${latest_url}" 2>&1 |
      awk '/^[[:space:]]*[Ll]ocation:/ { print $2 }' | tail -n 1 | tr -d '\r')" || true
  else
    die "Neither curl nor wget is available to resolve the latest release."
  fi

  if [[ "${effective_url}" =~ /tag/([^/?#]+)$ ]]; then
    tag="${BASH_REMATCH[1]}"
  else
    die "Could not resolve latest release tag from '${latest_url}'. Pass --version vX.Y.Z explicitly."
  fi

  validate_tag "${tag}"
  printf '%s\n' "${tag}"
}

parse_sha256sum() {
  local sums_file="$1"
  local target_name="$2"
  local line hash file
  local matches=0
  local found_hash=""

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line}" ]] && continue
    if [[ "${line}" =~ ^([0-9a-fA-F]{64})[[:space:]]+\*?(\./)?([^[:space:]]+)$ ]]; then
      hash="${BASH_REMATCH[1]}"
      file="${BASH_REMATCH[3]}"
      if [[ "${file}" == "${target_name}" ]]; then
        found_hash="${hash}"
        matches=$((matches + 1))
      fi
    fi
  done < "${sums_file}"

  if [[ "${matches}" -ne 1 ]]; then
    return 1
  fi

  printf '%s\n' "${found_hash}"
}

path_needs_sudo() {
  local target="$1"
  local probe="${target}"

  while [[ ! -e "${probe}" ]]; do
    local parent
    parent="$(dirname -- "${probe}")"
    if [[ "${parent}" == "${probe}" ]]; then
      break
    fi
    probe="${parent}"
  done

  if [[ -w "${probe}" ]]; then
    return 1
  fi
  return 0
}

compute_sudo_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then
    return 1
  fi
  if [[ "${SCOPE}" == "system" ]]; then
    return 0
  fi

  local dir
  for dir in "$@"; do
    if path_needs_sudo "${dir}"; then
      return 0
    fi
  done
  return 1
}

run_priv() {
  if [[ "${USE_SUDO}" -eq 1 ]]; then
    sudo -- "$@"
  else
    "$@"
  fi
}

find_fallback_file() {
  local base_dir="$1"
  shift
  local rel
  for rel in "$@"; do
    if [[ -f "${base_dir}/${rel}" && ! -L "${base_dir}/${rel}" && -s "${base_dir}/${rel}" ]]; then
      printf '%s\n' "${base_dir}/${rel}"
      return 0
    fi
  done
  return 1
}

set_mode() {
  local new_mode="$1"
  if [[ -n "${MODE}" && "${MODE}" != "${new_mode}" ]]; then
    die "Conflicting install modes: --${MODE} and --${new_mode} cannot be combined."
  fi
  MODE="${new_mode}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      --system)
        if [[ "${SCOPE}" == "prefix" ]]; then
          die "--system and --prefix cannot be used together."
        fi
        SCOPE="system"
        shift
        ;;
      --prefix)
        [[ $# -ge 2 ]] || die "Missing directory argument for --prefix."
        if [[ "${SCOPE}" == "system" ]]; then
          die "--system and --prefix cannot be used together."
        fi
        SCOPE="prefix"
        PREFIX="$2"
        shift 2
        ;;
      --prefix=*)
        if [[ "${SCOPE}" == "system" ]]; then
          die "--system and --prefix cannot be used together."
        fi
        SCOPE="prefix"
        PREFIX="${1#*=}"
        shift
        ;;
      --source)
        set_mode "source"
        shift
        ;;
      --release)
        set_mode "release"
        shift
        ;;
      --bin)
        [[ $# -ge 2 ]] || die "Missing path argument for --bin."
        set_mode "bin"
        BIN_PATH="$2"
        shift 2
        ;;
      --bin=*)
        set_mode "bin"
        BIN_PATH="${1#*=}"
        shift
        ;;
      --version)
        [[ $# -ge 2 ]] || die "Missing tag argument for --version."
        VERSION="$2"
        shift 2
        ;;
      --version=*)
        VERSION="${1#*=}"
        shift
        ;;
      --repo)
        [[ $# -ge 2 ]] || die "Missing repository argument for --repo."
        REPO="$2"
        shift 2
        ;;
      --repo=*)
        REPO="${1#*=}"
        shift
        ;;
      --no-completions)
        INSTALL_COMPLETIONS=0
        shift
        ;;
      --no-man)
        INSTALL_MAN=0
        shift
        ;;
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      *)
        die "Unknown option: $1 (see --help)"
        ;;
    esac
  done
}

main() {
  parse_args "$@"

  local script_dir=""
  script_dir="$(detect_script_dir || true)"

  if [[ -z "${MODE}" ]]; then
    if is_local_checkout "${script_dir}" && command -v cargo >/dev/null 2>&1; then
      MODE="source"
    else
      MODE="release"
    fi
  fi

  local bin_dir data_dir bash_comp_dir zsh_comp_dir fish_comp_dir man_dir
  case "${SCOPE}" in
    user)
      [[ -n "${HOME:-}" ]] || die "HOME environment variable is not set."
      bin_dir="${HOME}/.local/bin"
      data_dir="${XDG_DATA_HOME:-${HOME}/.local/share}"
      ;;
    system)
      bin_dir="/usr/local/bin"
      data_dir="/usr/local/share"
      ;;
    prefix)
      PREFIX="$(normalize_and_validate_prefix "${PREFIX}")"
      bin_dir="${PREFIX}/bin"
      data_dir="${PREFIX}/share"
      ;;
  esac

  bash_comp_dir="${data_dir}/bash-completion/completions"
  zsh_comp_dir="${data_dir}/zsh/site-functions"
  fish_comp_dir="${data_dir}/fish/vendor_completions.d"
  man_dir="${data_dir}/man/man1"

  local -a check_dirs=("${bin_dir}")
  if [[ "${INSTALL_COMPLETIONS}" -eq 1 ]]; then
    check_dirs+=("${bash_comp_dir}" "${zsh_comp_dir}" "${fish_comp_dir}")
  fi
  if [[ "${INSTALL_MAN}" -eq 1 ]]; then
    check_dirs+=("${man_dir}")
  fi

  USE_SUDO=0
  if compute_sudo_needed "${check_dirs[@]}"; then
    USE_SUDO=1
    if [[ "${DRY_RUN}" -eq 0 ]]; then
      require_cmd sudo
    fi
  fi

  if [[ -n "${VERSION}" && "${VERSION}" != "latest" ]]; then
    validate_tag "${VERSION}"
  fi

  local resolved_repo="${REPO}"
  local release_base_url=""
  local target_triple=""
  local asset_name=""
  local download_base=""

  case "${MODE}" in
    source)
      is_local_checkout "${script_dir}" ||
        die "--source requires running from a local install-appimage repository checkout."
      if [[ "${DRY_RUN}" -eq 0 ]]; then
        require_cmd cargo
      fi
      ;;
    bin)
      validate_no_ctrl "Binary path" "${BIN_PATH}"
      [[ -f "${BIN_PATH}" ]] || die "Binary not found at '${BIN_PATH}'."
      [[ -r "${BIN_PATH}" ]] || die "Binary is not readable: '${BIN_PATH}'."
      ;;
    release)
      target_triple="$(detect_target_triple)"
      if [[ -n "${RELEASE_BASE_URL}" ]]; then
        release_base_url="$(validate_release_base_url "${RELEASE_BASE_URL}")"
      else
        if [[ -z "${resolved_repo}" ]]; then
          resolved_repo="$(detect_repo_from_git "${script_dir}" || true)"
        fi
        if [[ -z "${resolved_repo}" ]]; then
          die "GitHub repository not specified. Pass --repo OWNER/REPO or set INSTALL_APPIMAGE_REPO=OWNER/REPO."
        fi
        validate_repo "${resolved_repo}"
        release_base_url="https://github.com/${resolved_repo}/releases"
      fi

      if [[ -z "${VERSION}" || "${VERSION}" == "latest" ]]; then
        if [[ "${DRY_RUN}" -eq 1 ]]; then
          VERSION="<latest>"
        else
          VERSION="$(resolve_latest_tag "${release_base_url}")"
        fi
      fi

      asset_name="${APP_NAME}-${VERSION}-${target_triple}.tar.gz"
      download_base="${release_base_url}/download/${VERSION}"
      ;;
  esac

  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "[dry-run] Mode: ${MODE}"
    log "[dry-run] Scope: ${SCOPE}"
    if [[ "${USE_SUDO}" -eq 1 ]]; then
      log "[dry-run] Privilege elevation: sudo required for target paths"
    fi
    case "${MODE}" in
      source)
        log "[dry-run] Would build release binary: cargo build --release --locked (in ${script_dir})"
        ;;
      bin)
        log "[dry-run] Would install existing binary: ${BIN_PATH}"
        ;;
      release)
        if [[ -n "${RELEASE_BASE_URL}" ]]; then
          log "[dry-run] Release base URL: ${release_base_url} (${VERSION}, target: ${target_triple})"
        else
          log "[dry-run] Repository: ${resolved_repo} (${VERSION}, target: ${target_triple})"
        fi
        log "[dry-run] Would download ${download_base}/SHA256SUMS.txt"
        log "[dry-run] Would download ${download_base}/${asset_name} and verify SHA-256"
        log "[dry-run] Would extract with tar --no-same-owner --no-same-permissions -xzf"
        ;;
    esac
    log "[dry-run] Would install binary -> ${bin_dir}/${DEFAULT_BIN_NAME}"
    if [[ "${INSTALL_COMPLETIONS}" -eq 1 ]]; then
      log "[dry-run] Would install bash completion -> ${bash_comp_dir}/${DEFAULT_BIN_NAME}"
      log "[dry-run] Would install zsh completion  -> ${zsh_comp_dir}/_${DEFAULT_BIN_NAME}"
      log "[dry-run] Would install fish completion -> ${fish_comp_dir}/${DEFAULT_BIN_NAME}.fish"
    fi
    if [[ "${INSTALL_MAN}" -eq 1 ]]; then
      log "[dry-run] Would install manpage -> ${man_dir}/${DEFAULT_BIN_NAME}.1.gz"
    fi
    exit 0
  fi

  require_cmd install
  TMP_DIR="$(mktemp -d)"

  local src_bin=""
  local extract_dir=""

  case "${MODE}" in
    source)
      log "Building ${APP_NAME} (release, locked)..."
      (
        cd -- "${script_dir}"
        cargo build --release --locked
      )
      src_bin="${script_dir}/target/release/${DEFAULT_BIN_NAME}"
      [[ -f "${src_bin}" && -x "${src_bin}" ]] || die "Built binary not found at '${src_bin}'."
      ;;
    bin)
      src_bin="${BIN_PATH}"
      if [[ ! -x "${src_bin}" ]]; then
        cp -- "${src_bin}" "${TMP_DIR}/${DEFAULT_BIN_NAME}"
        chmod 0755 -- "${TMP_DIR}/${DEFAULT_BIN_NAME}"
        src_bin="${TMP_DIR}/${DEFAULT_BIN_NAME}"
      fi
      ;;
    release)
      require_cmd sha256sum
      require_cmd tar

      log "Downloading ${APP_NAME} ${VERSION} (${target_triple}) from ${resolved_repo:-${release_base_url}}..."
      http_download "${download_base}/SHA256SUMS.txt" "${TMP_DIR}/SHA256SUMS.txt"
      http_download "${download_base}/${asset_name}" "${TMP_DIR}/${asset_name}"

      local expected_sha=""
      expected_sha="$(parse_sha256sum "${TMP_DIR}/SHA256SUMS.txt" "${asset_name}")" ||
        die "Valid SHA-256 entry for '${asset_name}' not found in SHA256SUMS.txt."

      log "Verifying SHA-256 checksum..."
      printf '%s  %s\n' "${expected_sha}" "${TMP_DIR}/${asset_name}" | sha256sum -c -

      extract_dir="${TMP_DIR}/extract"
      mkdir -p -- "${extract_dir}"
      tar --no-same-owner --no-same-permissions -xzf "${TMP_DIR}/${asset_name}" -C "${extract_dir}"

      src_bin="${extract_dir}/${DEFAULT_BIN_NAME}"
      [[ -f "${src_bin}" && ! -L "${src_bin}" ]] || die "Expected binary '${DEFAULT_BIN_NAME}' missing from archive."
      chmod 0755 -- "${src_bin}"
      ;;
  esac

  local stage_dir="${TMP_DIR}/stage"
  mkdir -p -- "${stage_dir}"

  log "Installing binary to ${bin_dir}/${DEFAULT_BIN_NAME}..."
  run_priv install -d -m 0755 -- "${bin_dir}"
  run_priv install -m 0755 -- "${src_bin}" "${bin_dir}/${DEFAULT_BIN_NAME}"

  local installed_bin="${bin_dir}/${DEFAULT_BIN_NAME}"

  if [[ "${INSTALL_COMPLETIONS}" -eq 1 ]]; then
    local bash_stage="${stage_dir}/${DEFAULT_BIN_NAME}.bash"
    local zsh_stage="${stage_dir}/_${DEFAULT_BIN_NAME}"
    local fish_stage="${stage_dir}/${DEFAULT_BIN_NAME}.fish"
    local fallback=""

    if "${installed_bin}" --generate-completion bash > "${bash_stage}" 2>/dev/null && [[ -s "${bash_stage}" ]]; then
      :
    elif [[ -n "${extract_dir}" ]] && fallback="$(find_fallback_file "${extract_dir}" "completions/${DEFAULT_BIN_NAME}.bash" "completions/${DEFAULT_BIN_NAME}" "${DEFAULT_BIN_NAME}.bash")"; then
      cp -- "${fallback}" "${bash_stage}"
    else
      rm -f -- "${bash_stage}"
      warn "Could not generate or locate bash completion; skipping."
    fi

    if "${installed_bin}" --generate-completion zsh > "${zsh_stage}" 2>/dev/null && [[ -s "${zsh_stage}" ]]; then
      :
    elif [[ -n "${extract_dir}" ]] && fallback="$(find_fallback_file "${extract_dir}" "completions/_${DEFAULT_BIN_NAME}" "_${DEFAULT_BIN_NAME}")"; then
      cp -- "${fallback}" "${zsh_stage}"
    else
      rm -f -- "${zsh_stage}"
      warn "Could not generate or locate zsh completion; skipping."
    fi

    if "${installed_bin}" --generate-completion fish > "${fish_stage}" 2>/dev/null && [[ -s "${fish_stage}" ]]; then
      :
    elif [[ -n "${extract_dir}" ]] && fallback="$(find_fallback_file "${extract_dir}" "completions/${DEFAULT_BIN_NAME}.fish" "${DEFAULT_BIN_NAME}.fish")"; then
      cp -- "${fallback}" "${fish_stage}"
    else
      rm -f -- "${fish_stage}"
      warn "Could not generate or locate fish completion; skipping."
    fi

    if [[ -s "${bash_stage}" ]]; then
      run_priv install -d -m 0755 -- "${bash_comp_dir}"
      run_priv install -m 0644 -- "${bash_stage}" "${bash_comp_dir}/${DEFAULT_BIN_NAME}"
      log "Installed bash completion: ${bash_comp_dir}/${DEFAULT_BIN_NAME}"
    fi
    if [[ -s "${zsh_stage}" ]]; then
      run_priv install -d -m 0755 -- "${zsh_comp_dir}"
      run_priv install -m 0644 -- "${zsh_stage}" "${zsh_comp_dir}/_${DEFAULT_BIN_NAME}"
      log "Installed zsh completion:  ${zsh_comp_dir}/_${DEFAULT_BIN_NAME}"
    fi
    if [[ -s "${fish_stage}" ]]; then
      run_priv install -d -m 0755 -- "${fish_comp_dir}"
      run_priv install -m 0644 -- "${fish_stage}" "${fish_comp_dir}/${DEFAULT_BIN_NAME}.fish"
      log "Installed fish completion: ${fish_comp_dir}/${DEFAULT_BIN_NAME}.fish"
    fi
  fi

  if [[ "${INSTALL_MAN}" -eq 1 ]]; then
    if command -v gzip >/dev/null 2>&1; then
      local man_raw="${stage_dir}/${DEFAULT_BIN_NAME}.1"
      local man_gz="${stage_dir}/${DEFAULT_BIN_NAME}.1.gz"
      local fallback=""

      if "${installed_bin}" --generate-man > "${man_raw}" 2>/dev/null && [[ -s "${man_raw}" ]]; then
        gzip -9n -c -- "${man_raw}" > "${man_gz}"
      elif [[ -n "${extract_dir}" ]] && fallback="$(find_fallback_file "${extract_dir}" "man/${DEFAULT_BIN_NAME}.1.gz" "${DEFAULT_BIN_NAME}.1.gz")"; then
        cp -- "${fallback}" "${man_gz}"
      elif [[ -n "${extract_dir}" ]] && fallback="$(find_fallback_file "${extract_dir}" "man/${DEFAULT_BIN_NAME}.1" "${DEFAULT_BIN_NAME}.1")"; then
        gzip -9n -c -- "${fallback}" > "${man_gz}"
      else
        warn "Could not generate or locate manpage; skipping."
      fi

      if [[ -s "${man_gz}" ]]; then
        run_priv install -d -m 0755 -- "${man_dir}"
        run_priv install -m 0644 -- "${man_gz}" "${man_dir}/${DEFAULT_BIN_NAME}.1.gz"
        log "Installed manpage:         ${man_dir}/${DEFAULT_BIN_NAME}.1.gz"
      fi
    else
      warn "gzip not found; skipping manpage installation."
    fi
  fi

  if [[ "${SCOPE}" == "user" ]]; then
    case ":${PATH:-}:" in
      *":${bin_dir}:"*)
        ;;
      *)
        warn "${bin_dir} is not in your PATH."
        log "Add it to your shell configuration, e.g.:"
        log "  export PATH=\"${bin_dir}:\$PATH\""
        ;;
    esac
  fi

  log "Done! Run '${DEFAULT_BIN_NAME} --doctor' to check your environment."
}

main "$@"

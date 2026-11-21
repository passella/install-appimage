#!/usr/bin/env bash
set -euo pipefail

readonly APP_NAME="install-appimage"

SCOPE="user"
PREFIX=""
DRY_RUN=0
USE_SUDO=0

usage() {
  cat <<'EOF'
Usage: uninstall.sh [OPTIONS]

Uninstall install-appimage binary, shell completions, and manpage.
Managed AppImages (~/Applications) and registry.json are always preserved.

Scope (must match installation scope; default: user-level XDG paths):
  --system              Uninstall from /usr/local (uses sudo if needed)
  --prefix <DIR>        Uninstall from custom prefix <DIR>

Options:
  --dry-run             Show files that would be removed without deleting anything
  -h, --help            Show this help message
EOF
}

log() {
  printf '%s\n' "$*"
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

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

file_needs_sudo() {
  local target="$1"
  local parent
  parent="$(dirname -- "${target}")"

  if [[ -e "${target}" || -L "${target}" ]]; then
    if [[ ! -w "${parent}" ]]; then
      return 0
    fi
  fi
  return 1
}

compute_sudo_needed() {
  if [[ "$(id -u)" -eq 0 ]]; then
    return 1
  fi
  if [[ "${SCOPE}" == "system" ]]; then
    return 0
  fi

  local item
  for item in "$@"; do
    if file_needs_sudo "${item}"; then
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

  local bin_dir data_dir
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

  local -a targets=(
    "${bin_dir}/${APP_NAME}"
    "${data_dir}/bash-completion/completions/${APP_NAME}"
    "${data_dir}/zsh/site-functions/_${APP_NAME}"
    "${data_dir}/fish/vendor_completions.d/${APP_NAME}.fish"
    "${data_dir}/man/man1/${APP_NAME}.1.gz"
  )

  if compute_sudo_needed "${targets[@]}"; then
    USE_SUDO=1
    if [[ "${DRY_RUN}" -eq 0 ]]; then
      require_cmd sudo
    fi
  fi

  local removed=0
  local target
  for target in "${targets[@]}"; do
    if [[ -e "${target}" || -L "${target}" ]]; then
      if [[ "${DRY_RUN}" -eq 1 ]]; then
        log "[dry-run] Would remove: ${target}"
      else
        run_priv rm -f -- "${target}"
        log "Removed: ${target}"
      fi
      removed=$((removed + 1))
    else
      if [[ "${DRY_RUN}" -eq 1 ]]; then
        log "[dry-run] Not present: ${target}"
      fi
    fi
  done

  if [[ "${removed}" -eq 0 ]]; then
    log "No ${APP_NAME} installation artifacts found under scope '${SCOPE}'."
  fi

  local registry_dir="${XDG_DATA_HOME:-${HOME:-~}/.local/share}/install-appimage"
  log ""
  log "Preserved user data (not removed):"
  log "  - Managed AppImages: ${HOME:-~}/Applications"
  log "  - Registry state:    ${registry_dir}/registry.json"
}

main "$@"

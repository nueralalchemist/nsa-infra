#!/usr/bin/env bash
# Shared helpers for the NSA shell installer. Sourced, not executed.

DRY_RUN="${DRY_RUN:-0}"

log()  { printf '\033[1;34m[nsa]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[nsa:warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[nsa:error]\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# Run a command, or just print it in --dry-run mode.
run() {
  if [[ "$DRY_RUN" == 1 ]]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}

need_root() {
  [[ "$DRY_RUN" == 1 || $EUID -eq 0 ]] || die "run as root: sudo $0 $*"
}

has_systemd() { [[ -d /run/systemd/system ]]; }

# Parse a KEY=VALUE file into the environment WITHOUT executing it.
# Existing environment variables win over the file.
load_vars() {
  local file="$1" line key val
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"; line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]] || die "bad line in $file: $line"
    key="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
    [[ -n "${!key+x}" ]] || export "$key=$val"
  done <"$file"
}

apply_defaults() {
  : "${NSA_EXPOSE:=tailscale}" "${NSA_GATEWAY_PORT:=4000}" "${NSA_TS_HOSTNAME:=nsa-cloud}"
  : "${NSA_MODEL_MAIN_CLOUD:=qwen3:4b-instruct}" "${NSA_MODEL_FAST_CLOUD:=qwen3:4b-instruct}" "${NSA_EXTRA_MODELS:=}"
  : "${NSA_OLLAMA_KEEP_ALIVE:=10m}" "${NSA_OLLAMA_MAX_LOADED:=1}" "${NSA_OLLAMA_NUM_PARALLEL:=1}"
  : "${NSA_LITELLM_VERSION:=}" "${NSA_OLLAMA_INSTALL_SHA256:=}" "${NSA_MIN_DISK_GB:=10}"
  case "$NSA_EXPOSE" in tailscale|localhost) ;; *) die "NSA_EXPOSE must be tailscale or localhost" ;; esac
  [[ "$NSA_GATEWAY_PORT" =~ ^[0-9]+$ ]] || die "NSA_GATEWAY_PORT must be a number"
  local m
  for m in "$NSA_MODEL_MAIN_CLOUD" "$NSA_MODEL_FAST_CLOUD" $NSA_EXTRA_MODELS; do
    [[ "$m" =~ ^[A-Za-z0-9._:/-]+$ ]] || die "invalid model name: $m"
  done
}

detect_os() {
  [[ -r /etc/os-release ]] || die "cannot detect OS"
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-}"; OS_CODENAME="${VERSION_CODENAME:-}"
  case "$OS_ID" in ubuntu|debian) ;; *) die "supported: Ubuntu or Debian (found: ${OS_ID:-unknown})" ;; esac
  [[ -n "$OS_CODENAME" ]] || die "cannot determine OS codename"
  case "$(uname -m)" in x86_64|aarch64) ;; *) die "unsupported CPU: $(uname -m)" ;; esac
}

# Free space needed on /. A fresh install needs the full amount (Ollama ~2.5 GB, a 4B model ~2.5 GB, LiteLLM ~0.75 GB,
# plus headroom). A box that already has the stack installed has legitimately used that space, so a re-run (repair,
# update, key rotation) only needs a small safety margin.
required_disk_gb() {
  if have ollama && [[ -x "${VENV_DIR:-/opt/nsa/venv}/bin/litellm" ]]; then echo 2; else echo "$NSA_MIN_DISK_GB"; fi
}

check_disk() {
  local free_gb need; need=$(required_disk_gb)
  free_gb=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  log "free disk on /: ${free_gb}GB (need ${need}GB)"
  (( free_gb >= need )) || die "not enough disk space: ${free_gb}GB free, need ${need}GB"
}

# Download URL to DEST. If SHA256 is given the file must match; otherwise print the hash for the record.
fetch_file() {
  local url="$1" dest="$2" want="${3:-}" got
  log "downloading $url"
  run curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
  [[ "$DRY_RUN" == 1 ]] && return 0
  got=$(sha256sum "$dest" | cut -d' ' -f1)
  if [[ -n "$want" ]]; then
    [[ "$got" == "$want" ]] || die "checksum mismatch for $url (got $got)"
    log "checksum verified"
  else
    warn "no checksum pinned for $url; sha256=$got (pin it via NSA_OLLAMA_INSTALL_SHA256)"
  fi
}

# Write stdin to PATH with MODE and OWNER:GROUP (atomic replace).
write_file() {
  local path="$1" mode="$2" owner="$3" tmp
  if [[ "$DRY_RUN" == 1 ]]; then printf '  [dry-run] write %s (%s %s)\n' "$path" "$mode" "$owner"; cat >/dev/null; return 0; fi
  tmp=$(mktemp)
  cat >"$tmp"
  install -D -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$tmp" "$path"
  rm -f "$tmp"
}

# Idempotently set KEY=VALUE in an env file (creates it if missing).
set_env_kv() {
  local file="$1" key="$2" val="$3" tmp
  if [[ "$DRY_RUN" == 1 ]]; then printf '  [dry-run] set %s in %s\n' "$key" "$file"; return 0; fi
  touch "$file"
  tmp=$(mktemp)
  awk -v k="$key" -v v="$val" 'BEGIN{FS=OFS="="} $1==k{print k "=" v; f=1; next} {print} END{if(!f) print k "=" v}' "$file" >"$tmp"
  cat "$tmp" >"$file"; rm -f "$tmp"
}

get_env_kv() { grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2-; }

# Unique, order-preserving list of the models to serve.
model_list() {
  # shellcheck disable=SC2086  # NSA_EXTRA_MODELS is a validated, space-separated list
  printf '%s\n' "$NSA_MODEL_MAIN_CLOUD" "$NSA_MODEL_FAST_CLOUD" $NSA_EXTRA_MODELS | awk 'NF && !seen[$0]++'
}

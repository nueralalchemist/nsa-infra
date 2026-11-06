#!/usr/bin/env bash
# Client role: install the nsa CLI on WSL/Mac/Linux and point it at the cloud gateway.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

client_main() {
  local cloud_url="${NSA_CLOUD_URL:-}" cloud_key="${NSA_CLOUD_KEY:-}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cloud-url) cloud_url="${2:?--cloud-url needs a value}"; shift 2 ;;
      --cloud-key-file) cloud_key="$(<"${2:?--cloud-key-file needs a path}")"; shift 2 ;;
      *) die "unknown client option: $1" ;;
    esac
  done

  have python3 || die "python3 is required"
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || die "python 3.10+ is required"
  python3 -c 'import venv, ensurepip' 2>/dev/null || die "python venv support missing (Debian/Ubuntu: apt install python3-venv)"

  log "installing nsa from $REPO_ROOT"
  [[ -d "$REPO_ROOT/.venv" ]] || run python3 -m venv "$REPO_ROOT/.venv"
  run "$REPO_ROOT/.venv/bin/pip" install -q --upgrade pip
  run "$REPO_ROOT/.venv/bin/pip" install -q -e "$REPO_ROOT"

  local envfile="$REPO_ROOT/.env"
  if [[ ! -f "$envfile" ]]; then
    log "creating .env from .env.example"
    run cp "$REPO_ROOT/.env.example" "$envfile"
  fi
  run chmod 600 "$envfile"

  if [[ -n "$cloud_url" ]]; then
    [[ "$cloud_url" =~ ^https?://[A-Za-z0-9._:-]+(/.*)?$ ]] || die "invalid --cloud-url: $cloud_url"
    [[ "$cloud_url" == */v1 ]] || warn "cloud URL does not end in /v1; the gateway serves the OpenAI API under /v1"
    set_env_kv "$envfile" NSA_CLOUD_URL "$cloud_url"
    if [[ -z "$cloud_key" && -t 0 && "$DRY_RUN" != 1 ]]; then
      read -r -s -p "Gateway API key (LITELLM_MASTER_KEY; Enter to skip): " cloud_key; echo
    fi
    [[ -n "$cloud_key" ]] && set_env_kv "$envfile" NSA_CLOUD_KEY "$cloud_key"
    # Keep model names in step with what the server serves, if infra.env defines them.
    [[ -n "${NSA_MODEL_MAIN_CLOUD:-}" ]] && set_env_kv "$envfile" NSA_MODEL_MAIN_CLOUD "$NSA_MODEL_MAIN_CLOUD"
    [[ -n "${NSA_MODEL_FAST_CLOUD:-}" ]] && set_env_kv "$envfile" NSA_MODEL_FAST_CLOUD "$NSA_MODEL_FAST_CLOUD"
  else
    warn "no --cloud-url given: cloud mode stays disabled (local mode still works)"
  fi

  log "running: nsa doctor"
  run "$REPO_ROOT/.venv/bin/nsa" doctor || warn "doctor reported problems (expected if the local model or gateway is not up yet)"
  cat <<EOF

nsa installed. Activate with:  source $REPO_ROOT/.venv/bin/activate
EOF
}

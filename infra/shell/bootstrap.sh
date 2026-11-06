#!/usr/bin/env bash
# NSA infrastructure bootstrap: the "normal" (shell) edition.
#   sudo infra/shell/bootstrap.sh server      # build the gateway host (Ollama + LiteLLM [+ Tailscale])
#        infra/shell/bootstrap.sh client      # install the nsa CLI and point it at a gateway
#        infra/shell/bootstrap.sh verify      # smoke-test a running gateway
#        infra/shell/bootstrap.sh preflight   # read-only check that a machine can host the gateway
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib/common.sh
. "$HERE/lib/common.sh"
# shellcheck source=lib/server.sh
. "$HERE/lib/server.sh"
# shellcheck source=lib/client.sh
. "$HERE/lib/client.sh"

usage() {
  cat <<'EOF'
Usage: bootstrap.sh <preflight|server|client|verify> [options]

Options:
  --vars FILE        settings file (default: infra/infra.env if present)
  --dry-run          print what would happen, change nothing
  --cloud-url URL    (client) gateway URL, e.g. http://100.x.y.z:4000/v1
  --cloud-key-file F (client) read the gateway key from a file instead of prompting
  -h, --help         this help

Secrets are never read from the vars file by default: pass TAILSCALE_AUTHKEY as an
environment variable (or you will be prompted), and the gateway key is generated on the server.
EOF
}

main() {
  local cmd="${1:-}"; [[ $# -gt 0 ]] && shift
  local vars="$HERE/../infra.env" rest=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --vars) vars="${2:?--vars needs a path}"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) rest+=("$1"); shift ;;
    esac
  done
  export DRY_RUN
  load_vars "$vars"
  case "$cmd" in
    server) [[ ${#rest[@]} -eq 0 ]] || die "unexpected arguments: ${rest[*]-}"; server_main ;;
    client) client_main ${rest[@]+"${rest[@]}"} ;;  # ${arr[@]+...}: safe on macOS bash 3.2
    preflight) preflight_main ;;
    verify)
      apply_defaults
      # Use the address the gateway really binds to (the Tailscale IP in tailscale mode); the env file is root/nsa-readable only.
      local bind; bind=$(get_env_kv /etc/nsa/gateway.env NSA_BIND_ADDR 2>/dev/null || true)
      GATEWAY_URL="${GATEWAY_URL:-http://${bind:-127.0.0.1}:${NSA_GATEWAY_PORT}}" \
        EXPECT_MODELS="${EXPECT_MODELS:-$(model_list | tr '\n' ' ')}" "$HERE/../scripts/verify.sh" ;;
    ""|-h|--help|help) usage ;;
    *) usage; die "unknown command: $cmd" ;;
  esac
}

main "$@"

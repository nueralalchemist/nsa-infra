#!/usr/bin/env bash
# Server role: Tailscale (optional) + Ollama + LiteLLM gateway. Sourced by bootstrap.sh.

NSA_USER=nsa
ETC_DIR=/etc/nsa
STATE_DIR=/var/lib/nsa
VENV_DIR=/opt/nsa/venv
GATEWAY_ENV="$ETC_DIR/gateway.env"
GATEWAY_CFG="$ETC_DIR/litellm.yaml"

server_preflight() {
  detect_os
  check_disk
  log "RAM: $(awk '/MemTotal/{printf "%.1f GB", $2/1048576}' /proc/meminfo), CPUs: $(nproc), OS: $OS_ID $OS_CODENAME"
  has_systemd || warn "systemd not detected: services will be started with nohup and will not survive a reboot"
}

install_packages() {
  log "installing base packages"
  run apt-get -o DPkg::Lock::Timeout=300 update -qq
  run env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq curl ca-certificates gnupg python3 python3-venv jq zstd openssl util-linux
}

create_user_and_dirs() {
  log "creating user '$NSA_USER' and directories"
  if ! id "$NSA_USER" >/dev/null 2>&1; then
    run useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$NSA_USER"
  fi
  run install -d -m 0750 -o root -g "$NSA_USER" "$ETC_DIR"
  run install -d -m 0750 -o "$NSA_USER" -g "$NSA_USER" "$STATE_DIR"
  run install -d -m 0755 -o root -g root /opt/nsa
}

install_tailscale() {
  [[ "$NSA_EXPOSE" == tailscale ]] || { log "NSA_EXPOSE=localhost: skipping Tailscale"; return 0; }
  if ! have tailscale; then
    log "installing Tailscale from its signed apt repository"
    run curl -fsSL --proto '=https' --tlsv1.2 -o /usr/share/keyrings/tailscale-archive-keyring.gpg \
      "https://pkgs.tailscale.com/stable/${OS_ID}/${OS_CODENAME}.noarmor.gpg"
    run curl -fsSL --proto '=https' --tlsv1.2 -o /etc/apt/sources.list.d/tailscale.list \
      "https://pkgs.tailscale.com/stable/${OS_ID}/${OS_CODENAME}.tailscale-keyring.list"
    run apt-get -o DPkg::Lock::Timeout=300 update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -qq tailscale
  fi
  has_systemd && run systemctl enable --now tailscaled
  if [[ "$DRY_RUN" != 1 ]] && tailscale status >/dev/null 2>&1; then
    log "Tailscale already connected"
    return 0
  fi
  local keyfile
  if [[ -z "${TAILSCALE_AUTHKEY:-}" && -t 0 ]]; then
    read -r -s -p "Tailscale auth key (tskey-...): " TAILSCALE_AUTHKEY; echo
  fi
  [[ "$DRY_RUN" == 1 || -n "${TAILSCALE_AUTHKEY:-}" ]] || die "set TAILSCALE_AUTHKEY (a reusable, tagged, expiring key from the Tailscale admin console)"
  if [[ "$DRY_RUN" == 1 ]]; then
    printf '  [dry-run] tailscale up --hostname %s --auth-key=file:<tmp>\n' "$NSA_TS_HOSTNAME"; return 0
  fi
  keyfile=$(mktemp); chmod 600 "$keyfile"; printf '%s' "$TAILSCALE_AUTHKEY" >"$keyfile"
  tailscale up --hostname "$NSA_TS_HOSTNAME" --auth-key="file:$keyfile"
  rm -f "$keyfile"
}

bind_address() {
  if [[ "$NSA_EXPOSE" == localhost ]]; then echo 127.0.0.1; return; fi
  if [[ "$DRY_RUN" == 1 ]]; then echo "<tailscale-ip>"; return; fi
  local ip; ip=$(tailscale ip -4 2>/dev/null | head -1)
  [[ -n "$ip" ]] || die "Tailscale has no IPv4 address; is it connected?"
  echo "$ip"
}

install_ollama() {
  if have ollama; then
    log "Ollama already installed: $(ollama --version 2>&1 | tail -1)"
  else
    local tmp; tmp=$(mktemp)
    fetch_file "https://ollama.com/install.sh" "$tmp" "$NSA_OLLAMA_INSTALL_SHA256"
    run sh "$tmp"
    rm -f "$tmp"
  fi

  # The service runs as the unprivileged 'ollama' user. If the installer ran under a restrictive umask,
  # its CUDA backend dir ends up 0700 root-only and Ollama silently falls back to CPU. Make it readable.
  [[ -d /usr/local/lib/ollama ]] && run chmod -R a+rX /usr/local/lib/ollama

  if has_systemd; then
    log "configuring Ollama (localhost only, one model, one request at a time)"
    write_file /etc/systemd/system/ollama.service.d/nsa.conf 0644 root:root <<EOF
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_KEEP_ALIVE=${NSA_OLLAMA_KEEP_ALIVE}"
Environment="OLLAMA_MAX_LOADED_MODELS=${NSA_OLLAMA_MAX_LOADED}"
Environment="OLLAMA_NUM_PARALLEL=${NSA_OLLAMA_NUM_PARALLEL}"
EOF
    run systemctl daemon-reload
    run systemctl enable ollama
    run systemctl restart ollama
  else
    start_detached ollama "$STATE_DIR/ollama.log" env HOME="$STATE_DIR" OLLAMA_MODELS="$STATE_DIR/models" \
      OLLAMA_HOST=127.0.0.1:11434 OLLAMA_KEEP_ALIVE="$NSA_OLLAMA_KEEP_ALIVE" \
      OLLAMA_MAX_LOADED_MODELS="$NSA_OLLAMA_MAX_LOADED" OLLAMA_NUM_PARALLEL="$NSA_OLLAMA_NUM_PARALLEL" ollama serve
  fi
}

# Fallback when there is no systemd: run a command as the nsa user, detached, with a pidfile.
start_detached() {
  local name="$1" logfile="$2"; shift 2
  local pidfile="$STATE_DIR/$name.pid"
  if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    log "$name already running (pid $(cat "$pidfile"))"; return 0
  fi
  if [[ "$DRY_RUN" == 1 ]]; then printf '  [dry-run] start %s detached as %s\n' "$name" "$NSA_USER"; return 0; fi
  setsid nohup runuser -u "$NSA_USER" -- "$@" >>"$logfile" 2>&1 &
  echo $! >"$pidfile"
  log "$name started (pid $!), log: $logfile"
}

wait_for_ollama() {
  [[ "$DRY_RUN" == 1 ]] && { printf '  [dry-run] wait for Ollama API\n'; return 0; }
  local _
  for _ in $(seq 1 60); do
    curl -fsS -m 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && return 0
    sleep 2
  done
  die "Ollama API did not come up (check: journalctl -u ollama)"
}

# `ollama pull` redraws a progress bar with control codes; in a log that is thousands of lines. Keep one line per layer.
filter_pull_output() {
  tr '\r' '\n' | sed 's/\x1b\[[?0-9;]*[A-Za-z]//g' \
    | awk '/^pulling [0-9a-f]+: +100%/ { if (!seen[$2]++) print "  downloaded layer " substr($2, 1, length($2)-1); next } /^success/ || /[Ee]rror/ { print "  " $0 }'
}

pull_model() {
  if [[ "$DRY_RUN" == 1 ]]; then printf '  [dry-run] ollama pull %s\n' "$1"; return 0; fi
  ollama pull "$1" 2>&1 | filter_pull_output   # pipefail (set in bootstrap.sh) still fails the install if the pull fails
}

pull_models() {
  local m
  while read -r m; do
    if [[ "$DRY_RUN" != 1 ]] && ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$m"; then
      log "model $m already present"
    else
      log "pulling model $m (this can take a while on a small box)"
      pull_model "$m"
    fi
  done < <(model_list)
}

render_litellm_config() {
  {
    echo "model_list:"
    local m
    while read -r m; do
      printf '  - model_name: "%s"\n    litellm_params:\n      model: "ollama_chat/%s"\n      api_base: "http://127.0.0.1:11434"\n' "$m" "$m"
    done < <(model_list)
    cat <<'EOF'

general_settings:
  master_key: os.environ/LITELLM_MASTER_KEY

litellm_settings:
  drop_params: true
  telemetry: false
EOF
  } | write_file "$GATEWAY_CFG" 0640 "root:$NSA_USER"
}

install_gateway() {
  log "installing LiteLLM gateway into $VENV_DIR"
  # No pip cache: under `sudo -E` HOME is the invoking user's, so pip warns; and the cache would cost disk on small boxes.
  export PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
  [[ -x "$VENV_DIR/bin/python" || "$DRY_RUN" == 1 ]] || python3 -m venv "$VENV_DIR"
  run "$VENV_DIR/bin/pip" install -q --upgrade pip
  if [[ -n "$NSA_LITELLM_VERSION" ]]; then
    run "$VENV_DIR/bin/pip" install -q "litellm[proxy]==${NSA_LITELLM_VERSION}"
  else
    warn "NSA_LITELLM_VERSION is empty: installing the latest litellm. Pin it once validated."
    run "$VENV_DIR/bin/pip" install -q "litellm[proxy]"
  fi

  local bind; bind=$(bind_address)
  if [[ "$DRY_RUN" != 1 && ! -f "$GATEWAY_ENV" ]]; then
    log "generating gateway master key"
    ( umask 077; printf 'LITELLM_MASTER_KEY=sk-%s\n' "$(openssl rand -hex 24)" >"$GATEWAY_ENV" )
  fi
  set_env_kv "$GATEWAY_ENV" NSA_BIND_ADDR "$bind"
  set_env_kv "$GATEWAY_ENV" NSA_GATEWAY_PORT "$NSA_GATEWAY_PORT"
  set_env_kv "$GATEWAY_ENV" HOME "$STATE_DIR"
  run chown "root:$NSA_USER" "$GATEWAY_ENV"
  run chmod 0640 "$GATEWAY_ENV"
  render_litellm_config

  if has_systemd; then
    write_file /etc/systemd/system/nsa-gateway.service 0644 root:root <<EOF
[Unit]
Description=NSA LiteLLM gateway
After=network-online.target ollama.service tailscaled.service
Wants=network-online.target

[Service]
User=${NSA_USER}
Group=${NSA_USER}
EnvironmentFile=${GATEWAY_ENV}
ExecStart=${VENV_DIR}/bin/litellm --config ${GATEWAY_CFG} --host \${NSA_BIND_ADDR} --port \${NSA_GATEWAY_PORT}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=${STATE_DIR}
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
    run systemctl daemon-reload
    run systemctl enable nsa-gateway
    run systemctl restart nsa-gateway
  else
    # Load the env file inside the child so the master key never appears in `ps` output.
    # shellcheck disable=SC2016  # the $1/$@ must expand in the child shell, not here
    start_detached nsa-gateway "$STATE_DIR/gateway.log" \
      bash -c 'set -a; . "$1"; shift; exec "$@"' _ "$GATEWAY_ENV" \
      "$VENV_DIR/bin/litellm" --config "$GATEWAY_CFG" --host "$bind" --port "$NSA_GATEWAY_PORT"
  fi
}

# LiteLLM needs ~20 s after (re)start to import and load its config; verifying earlier gives a false failure.
wait_for_gateway() {
  local bind _
  bind=$(bind_address)
  if [[ "$DRY_RUN" == 1 ]]; then printf '  [dry-run] wait for the gateway to answer on %s:%s\n' "$bind" "$NSA_GATEWAY_PORT"; return 0; fi
  log "waiting for the gateway to start (up to 2 minutes)"
  for _ in $(seq 1 60); do
    curl -fsS -m 2 "http://${bind}:${NSA_GATEWAY_PORT}/health/liveliness" >/dev/null 2>&1 && return 0
    sleep 2
  done
  die "the gateway did not answer within 2 minutes (check: journalctl -u nsa-gateway --no-pager -n 50)"
}

verify_server() {
  local bind; bind=$(bind_address)
  log "verifying the stack"
  run env GATEWAY_URL="http://${bind}:${NSA_GATEWAY_PORT}" EXPECT_MODELS="$(model_list | tr '\n' ' ')" \
    "$(dirname "${BASH_SOURCE[0]}")/../../scripts/verify.sh"
}

print_connection_info() {
  local bind; bind=$(bind_address)
  cat <<EOF

================ NSA server ready ================
Gateway URL : http://${bind}:${NSA_GATEWAY_PORT}/v1
Models      : $(model_list | tr '\n' ' ')
API key     : sudo cat ${GATEWAY_ENV}   (LITELLM_MASTER_KEY)
EOF
  if [[ "$NSA_EXPOSE" == tailscale ]]; then
    cat <<EOF

On the client (WSL/Mac, joined to the same tailnet):
  infra/shell/bootstrap.sh client --cloud-url http://${bind}:${NSA_GATEWAY_PORT}/v1
EOF
  else
    cat <<EOF

Reach it from the client through an SSH tunnel:
  ssh -N -L ${NSA_GATEWAY_PORT}:127.0.0.1:${NSA_GATEWAY_PORT} <user>@<this-host>
  infra/shell/bootstrap.sh client --cloud-url http://127.0.0.1:${NSA_GATEWAY_PORT}/v1
EOF
  fi
  echo "=================================================="
}

# ---- preflight: read-only checks, safe to run on a brand-new machine before installing anything ----
_pf_fail=0
_pf() { # level label detail
  local color=32
  [[ "$1" == WARN ]] && color=33
  [[ "$1" == INFO ]] && color=36
  if [[ "$1" == FAIL ]]; then color=31; _pf_fail=1; fi
  printf '  \033[%sm%-4s\033[0m %-26s %s\n' "$color" "$1" "$2" "$3"
}

_pf_url() { # label url ; "reachable" means the server answered at all (a 404 still proves the network path works)
  local code
  code=$(curl -sS -m 10 -o /dev/null -I -w '%{http_code}' "$2" 2>/dev/null || true)
  if [[ -z "$code" || "$code" == 000 ]]; then _pf FAIL "reach $1" "$2: no response (DNS, firewall or no outbound internet); the installer downloads from here"
  elif [[ "$code" =~ ^5 ]]; then _pf WARN "reach $1" "$2 -> HTTP $code (server-side error; retry later)"
  else _pf PASS "reach $1" "$2 -> HTTP $code"; fi
}

preflight_main() {
  apply_defaults
  echo "NSA server preflight (checks only, changes nothing)"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      ubuntu|debian) _pf PASS "operating system" "${PRETTY_NAME:-$ID}" ;;
      *) _pf FAIL "operating system" "${PRETTY_NAME:-unknown}: the installer supports Ubuntu/Debian only (it uses apt)" ;;
    esac
  else
    _pf FAIL "operating system" "cannot read /etc/os-release"
  fi
  case "$(uname -m)" in
    x86_64|aarch64) _pf PASS "cpu architecture" "$(uname -m)" ;;
    *) _pf FAIL "cpu architecture" "$(uname -m) is unsupported" ;;
  esac

  if [[ $EUID -eq 0 ]]; then _pf PASS "privileges" "running as root"
  elif have sudo && sudo -n true 2>/dev/null; then _pf PASS "privileges" "passwordless sudo"
  elif have sudo; then _pf WARN "privileges" "sudo asks for a password; run the installer as: sudo -E ..."
  else _pf FAIL "privileges" "not root and no sudo available"; fi

  if [[ -d /run/systemd/system ]]; then _pf PASS "systemd" "present (services survive reboots)"
  else _pf WARN "systemd" "absent: the shell edition falls back to nohup (no restart after reboot); Ansible edition unusable"; fi

  local free_gb mem_gb cpus need_gb
  need_gb=$(required_disk_gb)
  free_gb=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  mem_gb=$(awk '/MemTotal/{printf "%.1f", $2/1048576}' /proc/meminfo)
  cpus=$(nproc)
  if (( free_gb >= need_gb )); then _pf PASS "free disk on /" "${free_gb} GB (need ${need_gb}$([[ $need_gb -lt $NSA_MIN_DISK_GB ]] && echo ', stack already installed'))"
  else _pf FAIL "free disk on /" "${free_gb} GB free, need ${need_gb}"; fi
  if awk -v m="$mem_gb" 'BEGIN{exit !(m >= 6)}'; then _pf PASS "memory" "${mem_gb} GB"
  else _pf WARN "memory" "${mem_gb} GB: a 4B model needs about 4 GB plus the OS; expect swapping"; fi
  if (( cpus >= 2 )); then _pf PASS "cpu cores" "$cpus"; else _pf WARN "cpu cores" "$cpus (inference will be very slow)"; fi
  if have systemd-detect-virt; then _pf INFO "virtualization" "$(systemd-detect-virt 2>/dev/null || echo unknown)"; fi

  if have curl; then _pf PASS "curl" "installed"; else _pf WARN "curl" "missing (the installer will apt-install it)"; fi
  if python3 -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then _pf PASS "python3 + venv" "$(python3 -V)"
  else _pf WARN "python3 + venv" "missing or too old (the installer will apt-install python3-venv)"; fi
  if ss -ltn 2>/dev/null | grep -qE ":${NSA_GATEWAY_PORT}\b"; then _pf FAIL "port ${NSA_GATEWAY_PORT}" "already in use"
  else _pf PASS "port ${NSA_GATEWAY_PORT}" "free"; fi

  if have curl; then
    _pf_url "Ollama installer" https://ollama.com/install.sh
    _pf_url "Ollama model registry" https://registry.ollama.ai/v2/library/qwen3/manifests/4b
    _pf_url "PyPI" https://pypi.org/simple/litellm/
    if [[ "$NSA_EXPOSE" == tailscale ]]; then
      _pf_url "Tailscale packages" https://pkgs.tailscale.com/stable/
      if [[ -c /dev/net/tun ]]; then _pf PASS "/dev/net/tun" "present (Tailscale kernel mode works)"
      else _pf WARN "/dev/net/tun" "missing: Tailscale would need userspace networking; prefer NSA_EXPOSE=localhost + SSH tunnel"; fi
    fi
  fi
  echo
  if (( _pf_fail )); then echo "RESULT: NOT READY (fix the FAIL lines above)"; return 1; fi
  echo "RESULT: ready to install"
}

print_pins() {
  [[ "$DRY_RUN" == 1 ]] && return 0
  local lv ov
  lv=$("$VENV_DIR/bin/pip" show litellm 2>/dev/null | awk '/^Version:/{print $2}')
  ov=$(ollama --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  cat <<EOF

Versions validated on this machine. Pin them in infra/infra.env so rebuilds are reproducible:
  NSA_LITELLM_VERSION=${lv:-unknown}
  (Ollama ${ov:-unknown}. The Ollama installer's sha256 was printed earlier in this log as "no checksum pinned ... sha256=...")
EOF
}

server_main() {
  need_root server
  umask 022   # files we create or that installers create must be readable by service users
  apply_defaults
  server_preflight
  install_packages
  create_user_and_dirs
  install_tailscale
  install_ollama
  wait_for_ollama
  pull_models
  install_gateway
  wait_for_gateway
  verify_server
  print_connection_info
  print_pins
}

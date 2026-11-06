# NSA infrastructure playbooks

> **Testing on a fresh machine? Follow [RUNBOOK.md](RUNBOOK.md)**: every command in order, with expected output.

Two editions that build the **same** result. Pick one.

| | Normal (shell) | Enterprise (Ansible) |
|---|---|---|
| Path | [`shell/`](shell/) | [`ansible/`](ansible/) |
| Needs | bash, curl, root | ansible-core, SSH or local connection |
| Idempotent re-runs | yes | yes, plus `--check --diff` previews |
| Settings | `infra/infra.env` | `ansible/group_vars/all.yml` (+ vault) |
| Fleet / multiple hosts | no | yes (inventory groups, tags, `--limit`) |
| Extras | nohup fallback when there is no systemd | opt-in hardening role (ufw + unattended-upgrades), lint-clean under `ansible-lint --profile production` |

Both are verified to render **identical** `litellm.yaml`, `nsa-gateway.service` and Ollama override files.

## What gets built

```
 your WSL / Mac                           cloud box (e.g. 4 vCPU / 8 GB / 20 GB)
 ┌───────────┐   tailnet or SSH tunnel    ┌─────────────────────────────────────────┐
 │ nsa CLI   │ ─────────────────────────▶ │ LiteLLM gateway  :4000 (key required)   │
 └───────────┘      /v1 (OpenAI API)      │      │                                  │
                                          │      ▼                                  │
                                          │ Ollama 127.0.0.1:11434 (not exposed)    │
                                          │ models: NSA_MODEL_MAIN/FAST_CLOUD       │
                                          └─────────────────────────────────────────┘
```

- **Ollama** listens on localhost only, one model and one request at a time (right for a small CPU box).
- **LiteLLM** is the only network-facing service. It requires the generated master key and binds to the Tailscale IP only (`NSA_EXPOSE=tailscale`) or `127.0.0.1` (`NSA_EXPOSE=localhost`, reach it through an SSH tunnel). It never binds to `0.0.0.0`.
- Runs as the unprivileged `nsa` user under a hardened systemd unit (`ProtectSystem=strict`, `NoNewPrivileges`, ...).
- State lives in git (config) and in nothing else: the box is disposable. Rebuild = run the installer again.

## Normal edition (shell)

```bash
cp infra/infra.env.example infra/infra.env      # edit models / exposure
export TAILSCALE_AUTHKEY=tskey-...               # only for NSA_EXPOSE=tailscale
infra/shell/bootstrap.sh preflight                   # read-only: can this machine host the gateway?
sudo -E infra/shell/bootstrap.sh server --dry-run   # preview, changes nothing
sudo -E infra/shell/bootstrap.sh server              # build the gateway host

# on your workstation:
infra/shell/bootstrap.sh client --cloud-url http://<gateway-ip>:4000/v1
infra/shell/bootstrap.sh verify
```

`sudo -E` keeps `TAILSCALE_AUTHKEY` in the environment. The auth key is passed to Tailscale through a private temp file, never written to disk permanently and never in `ps`.

## Enterprise edition (Ansible)

```bash
cd infra/ansible
python3 -m pip install ansible-core && ansible-galaxy collection install -r requirements.yml
cp inventory.example.ini inventory.ini           # add your host(s)
export TAILSCALE_AUTHKEY=tskey-...
ansible-playbook site.yml --check --diff --limit nsa_servers     # preview
ansible-playbook site.yml                                         # server + client
ansible-playbook site.yml --tags ollama,gateway,verify            # just part of it
```

Secrets: use `ansible-vault` for `nsa_cloud_key` and `tailscale_authkey` if you do not want them in the environment. Vault files matching `group_vars/*vault*` are git-ignored.

## The one-line infra upgrade

Moving to a bigger box means changing the model names and re-running the same installer:

```bash
# shell: infra/infra.env            # ansible: group_vars/all.yml
NSA_MODEL_MAIN_CLOUD=qwen3:14b      nsa_model_main_cloud: "qwen3:14b"
```

The client picks the new name up from the same value (`client` command or `nsa_client` role). Agents never name models, so nothing else changes.

## Safety notes

- **Supply chain.** Defaults install the latest LiteLLM and an unverified Ollama installer, and both editions *warn* about it. After validating (Phase 5), pin `NSA_LITELLM_VERSION` and `NSA_OLLAMA_INSTALL_SHA256` (the installer's hash is printed in the log). Tailscale comes from its signed apt repository.
- **Untrusted host.** A free/trial cloud box is a third party's machine. The gateway key and anything you send there are exposed to the provider. High-sensitivity agents are local-only in the CLI, and cloud prompts are redacted.
- **Open ports.** Nothing listens publicly by design. `nsa_enable_hardening: true` (Ansible) adds a default-deny firewall that still allows SSH and the tailnet gateway port; it is opt-in so a first run cannot lock you out.
- **Auth responses look odd, but it fails closed.** LiteLLM without a database rejects bad requests through error paths
  (HTTP 500 with no key, HTTP 400 `no_db_connection` with a wrong key, plus a traceback in its log) rather than a clean 401.
  Nothing is served or generated. `verify.sh` tests "was it rejected", and `nsa` recognises these shapes as "key rejected".
  Clean 401s and per-client keys need LiteLLM's database mode.
- **Rotating the key.** Delete `/etc/nsa/gateway.env` on the server and re-run the installer, then re-run the client step. Per-client keys need LiteLLM's database mode and are not part of this phase.
- **GPU boxes.** Both editions make `/usr/local/lib/ollama` world-readable after installing Ollama. Without that, a root-only CUDA directory makes Ollama silently fall back to CPU (found in Phase 3 testing on WSL, together with a truncated CUDA library from an interrupted download). Verify with `nsa doctor --warm` on the client.
- **First-boot apt lock.** Fresh cloud VMs run `unattended-upgrades` right after boot and hold the apt lock; both editions wait up to 5 minutes for it instead of failing.
- **Read-only service sandbox.** The gateway runs from a read-only virtualenv under `ProtectSystem=strict`. LiteLLM was tested in exactly that condition (read-only install, only its state directory writable): no permission errors, nothing written elsewhere.
- **No systemd.** The shell edition falls back to nohup (no restart after reboot). The Ansible edition requires systemd and says so.

## How the connection was tested (Phase 4)

A real LiteLLM gateway (configured by this directory's own shell installer code) ran on loopback in front of the local
Ollama, with a logging proxy between it and `nsa`. Verified: `verify.sh` passes (incl. no-key / wrong-key rejection), `nsa connect` and
`nsa doctor` round trip, secrets redacted on the wire, high-sensitivity agents blocked from the cloud (zero requests sent),
auto-mode fallback, wrong-key and unreachable-gateway messages. **Not yet verified:** Tailscale joining, a real SSH tunnel and
a remote machine: Phase 5.

## How this was tested (Phase 2)

Static and offline only, since a real install needs root on a throwaway machine:
`shellcheck` clean; `bash -n`; `--dry-run` of every shell path; real runs of the file helpers in a temp dir; `ansible-playbook --syntax-check`; `ansible-lint --profile production` passes; rendered-file parity between editions. **Real installs are Phase 3 (WSL client) and Phase 5 (fresh cloud box).**

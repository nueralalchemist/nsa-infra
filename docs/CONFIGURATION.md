# Configuration reference

NSA is configured with three kinds of input, from strongest to weakest:

1. **Real environment variables** (anything you `export`, or pass on the command line).
2. **`.env`** in the repository root, loaded at start-up *without* overriding variables that are already set. `nsa connect` writes to it. Copy [`.env.example`](../.env.example) to start; the file is git-ignored and created with mode 600.
3. **Defaults** written into the YAML files as `${VAR:-default}`.

Server installers have their own settings file ([`infra/infra.env`](../infra/infra.env.example) for the shell edition, [`group_vars/all.yml`](../infra/ansible/group_vars/all.yml) for Ansible); see [section 4](#4-installer-settings).

## 1. Client settings (read by `nsa`)

### Endpoints

| Variable | Default | Meaning |
|---|---|---|
| `NSA_LOCAL_URL` | `http://localhost:11434/v1` | OpenAI-compatible base URL for `local` mode (Ollama by default). |
| `NSA_LOCAL_KEY` | `ollama` | Bearer token sent to the local endpoint (Ollama ignores it). |
| `NSA_CLOUD_URL` | *(empty)* | Base URL of your gateway, e.g. `http://127.0.0.1:4000/v1`. **Empty disables cloud mode.** `nsa connect` sets this. |
| `NSA_CLOUD_KEY` | *(empty)* | Gateway API key. `nsa connect` sets this. |

### Models

| Variable | Default | Meaning |
|---|---|---|
| `NSA_MODEL_MAIN_LOCAL` | `qwen3:8b` | Model for the `main` alias in local mode. |
| `NSA_MODEL_FAST_LOCAL` | `qwen3:8b` | Model for the `fast` alias in local mode. |
| `NSA_MODEL_MAIN_CLOUD` | `qwen3:4b-instruct` | Model for `main` in cloud mode. **Must be a name the gateway serves.** |
| `NSA_MODEL_FAST_CLOUD` | `qwen3:4b-instruct` | Model for `fast` in cloud mode. |

`nsa doctor` compares these names with what each endpoint actually lists and prints `NOT FOUND on endpoint` on a mismatch.

### Reasoning and token budget

Some models "think" in hidden tokens before answering. That helps quality and costs time and tokens. Two knobs control it, each **per alias and per mode**:

| Variable | Default | Meaning |
|---|---|---|
| `NSA_MAIN_REASONING_LOCAL` / `_CLOUD` | *(empty)* | Value of `reasoning_effort` sent for the `main` alias. Empty = send nothing (model default). |
| `NSA_FAST_REASONING_LOCAL` | `none` | `fast` alias, local. `none` makes routing and classification quick. |
| `NSA_FAST_REASONING_CLOUD` | *(empty)* | `fast` alias, cloud. |
| `NSA_LLM_TIMEOUT` | `300` | Seconds to wait for one model response. Raise it on CPU-only machines. |

(`max_tokens` is 4096 per call, set under `defaults:` in `config/models.yaml`. Hidden reasoning counts against it.)

**Choosing a value.** What works depends on the model, and the wrong choice fails in different ways:

| Model type | Example | `none` | Empty (default) |
|---|---|---|---|
| **Hybrid** (can toggle thinking) | `qwen3:8b` | ✅ fast, no reasoning | ✅ better answers, slower |
| **Thinking-only** | `qwen3:4b` | ❌ **raw reasoning leaks into the answer** | ⚠️ works, but long tasks can exhaust the token budget (a SOC triage ran 3.5 min and returned nothing) |
| **Instruct / non-thinking** | `qwen3:4b-instruct` | n/a | ✅ fast, direct answers |

This is why the cloud default is `qwen3:4b-instruct` with empty reasoning settings. If the token budget runs out, `nsa` stops with an explicit error rather than returning an empty answer.

### Safety and paths

| Variable | Default | Meaning |
|---|---|---|
| `NSA_REDACT` | `standard` | Redaction level for cloud prompts: `standard`, `strict` (also all IPv4), or `off`. See [SECURITY.md](SECURITY.md#3-what-redaction-does-and-does-not-do). |
| `NSA_ALLOWED_PATHS` | *(empty)* | Extra directories agents may read, colon-separated. The current directory is always allowed. |
| `NSA_OUT` | `./nsa_out` | Where `write_file` may write (with approval). |
| `NSA_HOME` | `~/.nsa` | State directory; holds `audit.jsonl`. |
| `NSA_ROOT` | repository root | Where `config/`, `agents/` and `.env` are looked up. |
| `NSA_CONFIG_DIR` | `$NSA_ROOT/config` | Override the config directory. |
| `NSA_AGENTS_DIR` | `$NSA_ROOT/agents` | Override the agents directory. |

## 2. `config/models.yaml`

Maps **aliases** to real models, per mode. Agents ask for an alias, never a model name.

```yaml
aliases:
  main:                         # reasoning / generation
    reasoning_effort:           # optional; a string, or a per-mode mapping
      local: ${NSA_MAIN_REASONING_LOCAL:-}
      cloud: ${NSA_MAIN_REASONING_CLOUD:-}
    local: ${NSA_MODEL_MAIN_LOCAL:-qwen3:8b}
    cloud: ${NSA_MODEL_MAIN_CLOUD:-qwen3:4b-instruct}
  fast:                         # routing, classification, cheap steps
    reasoning_effort: {local: ${NSA_FAST_REASONING_LOCAL:-none}, cloud: ${NSA_FAST_REASONING_CLOUD:-}}
    local: ${NSA_MODEL_FAST_LOCAL:-qwen3:8b}
    cloud: ${NSA_MODEL_FAST_CLOUD:-qwen3:4b-instruct}
defaults:
  temperature: 0.2
  max_tokens: 4096
  timeout: ${NSA_LLM_TIMEOUT:-300}
```

| Key | Meaning |
|---|---|
| `aliases.<name>.local` / `.cloud` | Real model name sent to that endpoint. A missing entry for a mode is an error when that alias is used in that mode. |
| `aliases.<name>.reasoning_effort` | Sent as the OpenAI-style `reasoning_effort` field. A string applies to both modes; a mapping is per mode; empty means "do not send". |
| `aliases.<name>.no_think` | Legacy Qwen3 `/no_think` suffix for older Ollama. **Off by default**: current Ollama ignores it and thinking-only models echo it back. |
| `defaults.temperature`, `.max_tokens`, `.timeout` | Used for every call unless a caller overrides. |

You can add aliases; an agent selects one with `model:` in its manifest.

## 3. `config/endpoints.yaml`

```yaml
local: {base_url: ${NSA_LOCAL_URL:-http://localhost:11434/v1}, api_key: ${NSA_LOCAL_KEY:-ollama}}
cloud: {base_url: ${NSA_CLOUD_URL:-}, api_key: ${NSA_CLOUD_KEY:-}}
```

Both must implement `GET /models` and `POST /chat/completions` of the OpenAI API. Any such server works for either mode: Ollama, LiteLLM, vLLM, LM Studio.

## 4. Installer settings

Set these in `infra/infra.env` (shell edition) or the lowercase equivalents in `infra/ansible/group_vars/all.yml` (`NSA_EXPOSE` → `nsa_expose`). Process environment variables beat the file. Full reasoning in [DEPLOYMENT.md](DEPLOYMENT.md).

| Variable | Default | Meaning |
|---|---|---|
| `NSA_EXPOSE` | `tailscale` | `tailscale`: gateway binds to the Tailscale IP. `localhost`: binds `127.0.0.1`, reach it with an SSH tunnel. |
| `NSA_GATEWAY_PORT` | `4000` | Gateway port. |
| `NSA_TS_HOSTNAME` | `nsa-cloud` | Tailscale hostname (tailscale mode). |
| `TAILSCALE_AUTHKEY` | *(env only)* | Reusable, tagged, expiring auth key; never stored in a file by the installer. |
| `NSA_MODEL_MAIN_CLOUD`, `NSA_MODEL_FAST_CLOUD` | `qwen3:4b-instruct` | Models pulled and served (deduplicated). Must match the client's values. |
| `NSA_EXTRA_MODELS` | *(empty)* | Extra **chat** models to pull and serve, space-separated. |
| `NSA_OLLAMA_KEEP_ALIVE` | `10m` | How long Ollama keeps a model loaded. |
| `NSA_OLLAMA_MAX_LOADED` | `1` | Models loaded at once. |
| `NSA_OLLAMA_NUM_PARALLEL` | `1` | Parallel requests. |
| `NSA_LITELLM_VERSION` | *(empty)* | Pin LiteLLM (`1.108.1` was validated). Empty = latest, with a warning. |
| `NSA_OLLAMA_INSTALL_SHA256` | *(empty)* | If set, the Ollama installer is refused unless it matches. |
| `NSA_MIN_DISK_GB` | `10` | Free space required on `/` for a **fresh** install. A box that already has the stack only needs 2 GB. |

Ansible-only: `nsa_enable_hardening` (default `false`), `nsa_ssh_port` (22), `nsa_sync_client_models` (`true`), `nsa_repo_path`, `nsa_cloud_url`, `nsa_cloud_key`.

### Files the installer manages on the server

| Path | Purpose | Mode |
|---|---|---|
| `/etc/nsa/gateway.env` | `LITELLM_MASTER_KEY` (generated once), `NSA_BIND_ADDR`, `NSA_GATEWAY_PORT`, `HOME` | `0640 root:nsa` |
| `/etc/nsa/litellm.yaml` | LiteLLM model list, rendered from the model settings | `0640 root:nsa` |
| `/etc/systemd/system/nsa-gateway.service` | The hardened gateway unit | `0644` |
| `/etc/systemd/system/ollama.service.d/nsa.conf` | Ollama drop-in (localhost bind, keep-alive, parallelism) | `0644` |
| `/opt/nsa/venv` | LiteLLM virtualenv (read-only to the service) | root-owned |
| `/var/lib/nsa` | Gateway state (`HOME` of the `nsa` user) | `0750 nsa` |

### Smoke-test variables (`infra/scripts/verify.sh`)

`GATEWAY_URL` (default `http://127.0.0.1:4000`), `GATEWAY_KEY` (falls back to `NSA_CLOUD_KEY`, then `/etc/nsa/gateway.env`), `EXPECT_MODELS` (space-separated names that must be served), `SKIP_COMPLETION=1`, `VERIFY_TIMEOUT` (seconds, default 900).

## 5. Common changes

**Use a bigger local model.** `NSA_MODEL_MAIN_LOCAL=qwen3:14b` (and `ollama pull` it). Nothing else changes.

**Use a bigger cloud model after upgrading the box.** Edit `NSA_MODEL_MAIN_CLOUD` / `NSA_MODEL_FAST_CLOUD` in `infra.env`, re-run the installer on the box (it pulls the model and re-renders the gateway config), then set the same names on the client:

```bash
nsa connect --url http://127.0.0.1:4000/v1 --key-file ~/nsa-gateway.key   # re-checks the names
```

**Point at a different OpenAI-compatible server.** Set `NSA_LOCAL_URL` (or `NSA_CLOUD_URL`) and make the model names match what its `/v1/models` lists.

**Slow CPU-only machine.** Raise `NSA_LLM_TIMEOUT`; prefer a non-reasoning model for the cloud alias.

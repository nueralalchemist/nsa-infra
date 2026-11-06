# Troubleshooting

Start with `nsa doctor` (add `--warm` on a GPU machine). It checks each endpoint, that your configured model names are really served, and GPU offload, and it says what is wrong in words.

| Symptom | Section |
|---|---|
| Everything is very slow, requests time out | [Ollama is using the CPU](#ollama-is-using-the-cpu-instead-of-the-gpu) |
| Empty answer, or "used its whole token budget on hidden reasoning" | [Empty replies](#empty-replies-or-token-budget-exhausted) |
| The answer starts with "Hmm, the user wants…" | [Reasoning leaks into the answer](#the-models-reasoning-appears-in-the-answer) |
| `AUTH FAILED` / "rejected the API key" | [Key rejected](#key-rejected) |
| `UNREACHABLE` | [Cloud unreachable](#cloud-unreachable) |
| `NOT FOUND on endpoint` | [Model name mismatch](#model-name-mismatch) |
| "path outside allowed roots" | [File access](#path-outside-allowed-roots) |
| "local-only" refusal | [Sensitivity gate](#this-agent-handles-high-sensitivity-data-and-is-local-only) |
| "tool … was not approved" | [Approvals](#a-tool-was-not-approved) |
| Installer: lock, disk, or gateway start | [Installer problems](#installer-problems) |
| Wrong agent chosen | [Routing](#the-wrong-agent-was-chosen) |
| Sigma rule problems | [detection_as_code](#detection_as_code-gives-a-warning) |

---

## Ollama is using the CPU instead of the GPU

**Symptom.** One short reply takes minutes; `nsa doctor --warm` prints `running on CPU only (0 MB in VRAM) but an NVIDIA GPU exists`.

**Why.** Ollama discovers GPUs at start-up and silently falls back to CPU if its CUDA backend cannot load. Two causes were found on a real WSL2 machine:

1. **Unreadable CUDA directory.** Ollama runs as the `ollama` user but `/usr/local/lib/ollama/cuda_v*` was `0700 root:root` (restrictive `umask` at install time).
2. **Truncated CUDA library.** An interrupted download left `libggml-cuda.so` short (≈ 218 MB missing); loading it crashed with `SIGBUS` and Ollama quietly used CPU.

**Check.**

```bash
journalctl -u ollama --no-pager | grep -i "inference compute" | tail -2     # library=cpu means no GPU
ls -ld /usr/local/lib/ollama/cuda_v*
nvidia-smi
```

**Fix.**

```bash
sudo chmod -R a+rX /usr/local/lib/ollama && sudo systemctl restart ollama       # cause 1
curl -fsSL https://ollama.com/install.sh | sh                                    # cause 2: reinstall; models are kept
nsa doctor --warm                                                                # should show MB in VRAM
```

Install Ollama with `umask 022` so it cannot recur. The shell and Ansible installers do this and also repair the permissions.

## Empty replies, or "token budget exhausted"

**Symptom.** `error: the cloud model used its whole token budget (4096) on hidden reasoning and produced no answer`, or an empty answer in older versions.

**Why.** Reasoning models spend tokens thinking; those tokens count against `max_tokens`.

**Fix (pick one).**
- Use a **non-thinking** model for that alias, e.g. `qwen3:4b-instruct`. This is the cloud default.
- If the model can toggle thinking (e.g. `qwen3:8b`), set `NSA_MAIN_REASONING_LOCAL=none` (or `_CLOUD`).
- Raise `defaults.max_tokens` in `config/models.yaml` (slower).

## The model's reasoning appears in the answer

**Symptom.** A one-word reply starts with *"Hmm, the user just asked me to…"* or contains `/no_think`. `verify.sh` fails with "hidden reasoning is probably leaking".

**Why.** `reasoning_effort: none` was sent to a **thinking-only** model (e.g. `qwen3:4b`). Such models cannot switch thinking off; Ollama then stops separating it from the answer.

**Fix.** Leave the reasoning variables empty for that model, or switch to an instruct variant (`qwen3:4b-instruct`). See [CONFIGURATION.md](CONFIGURATION.md#reasoning-and-token-budget).

## Key rejected

**Symptom.** `cloud AUTH FAILED: HTTP 400: the endpoint rejected the API key`, or `error: cloud endpoint rejected the API key (400)`.

**Note on status codes.** LiteLLM without a database rejects bad keys with HTTP **400** (`no_db_connection`) or **500** rather than 401. `nsa` recognises these. It still means "key rejected".

**Fix.** Re-read the key from the server and reconnect (the gateway key changes if the server was rebuilt):

```bash
ssh myhost "sudo grep '^LITELLM_MASTER_KEY=' /etc/nsa/gateway.env" | cut -d= -f2- > ~/nsa-gateway.key && chmod 600 ~/nsa-gateway.key
nsa connect --url http://127.0.0.1:4000/v1 --key-file ~/nsa-gateway.key
```

`nsa connect` keeps your previous key if the new one is rejected.

## Cloud unreachable

**Symptom.** `cloud UNREACHABLE: ConnectError` (or "timed out").

Work through, in order:

1. **Tunnel/tailnet up?** `nsa tunnel <host>` (or your provider's own port-forward tool, mapping the gateway's port 4000 to `127.0.0.1:4000`) must be running; in Tailscale mode `tailscale status` on both ends.
2. **Port busy locally?** The tunnel fails at once if `127.0.0.1:4000` is in use: `ss -ltn | grep :4000`.
3. **Gateway running?** On the host: `systemctl is-active nsa-gateway`, `sudo journalctl -u nsa-gateway -n 50`. After a restart it needs about 20 s.
4. **Machine paused?** Some providers pause idle machines (the provider used in our tests documents a 30-minute idle pause). Wake it and restart the tunnel.
5. **Right URL?** It must end in `/v1`; `nsa connect` adds it.

`-m auto` keeps working locally while the cloud is down.

## Model name mismatch

**Symptom.** `nsa doctor` shows `main -> qwen3:… NOT FOUND on endpoint`, or `endpoint does not serve model`.

**Fix.** Make the names agree on both sides: on the host the installer serves `NSA_MODEL_MAIN_CLOUD` / `NSA_MODEL_FAST_CLOUD`; the client reads the same variable names from `.env`. Locally, `ollama pull <name>`. `ollama list` and `nsa doctor` show what is available.

## path outside allowed roots

Agents may read only inside the current directory plus `NSA_ALLOWED_PATHS`. Run `nsa` from the project directory, or:

```bash
NSA_ALLOWED_PATHS=/var/log/myapp:/srv/reports nsa run -a soc_triage -f /var/log/myapp/alert.json "triage"
```

## This agent handles high-sensitivity data and is local-only

Intended behaviour: `soc_triage` and `malware_triage` refuse to use the cloud, and `-m auto` will not fall back to it. Run them locally. Only if you accept the exposure: `--allow-sensitive-cloud` (prompts are still redacted). See [SECURITY.md](SECURITY.md).

## A tool was not approved

`fetch_url` is a network tool: add `--yes` (or answer `y` at the prompt). `write_file` always needs an interactive `y`; with no terminal it is denied.

## Installer problems

| Message | Cause and fix |
|---|---|
| `Could not get lock /var/lib/dpkg/lock-frontend` | A fresh VM is running automatic updates. The installer waits up to 5 minutes; just wait or re-run. |
| `not enough disk space: N GB free, need M GB` | A fresh install needs 10 GB free on `/` (2 GB for a re-run). Free space or use a bigger root disk. |
| `the gateway did not answer within 2 minutes` | `sudo journalctl -u nsa-gateway --no-pager -n 50`. Check RAM and that the model finished downloading. |
| `RESULT: NOT READY` from `preflight` | Fix each `FAIL` line: unsupported OS, no internet to a required host, port 4000 taken. |
| `checksum mismatch` | `NSA_OLLAMA_INSTALL_SHA256` no longer matches Ollama's installer; update or clear it. |
| `NSA_LITELLM_VERSION is empty` (warning) | Informational: pin the version printed at the end of the install. |

If the install log is long, `grep -E 'PASS|FAIL|error|nsa'` it. Model downloads are summarised as one line per layer.

## The wrong agent was chosen

```bash
nsa route "your task"                 # shows each agent's score and why
nsa run -a soc_triage "your task"     # force it
```

Improve routing by adding distinctive words to the agent's `keywords:` or sharpening its `description:`.

## detection_as_code gives a warning

- *"self-test skipped: …unsupported"*: the rule uses a Sigma feature the local matcher does not implement (aggregation, `base64`, `cidr`). The rule is still validated, just not executed locally.
- *"rule is valid but failed its own self-test"*: after 3 attempts the rule still missed its own attack or matched normal events. Use it as a draft only.
- Always test the rule on your own data (`-f events.jsonl`).

## Other

| Symptom | Fix |
|---|---|
| `nsa: command not found` | `. .venv/bin/activate`, or run `./bin/nsa`. |
| `error: empty task` / unknown agent | Pass the task text; check `nsa list`. |
| Timeouts on a slow machine | Raise `NSA_LLM_TIMEOUT`. |

## Collecting diagnostics for a bug report

None of these print secrets. Do **not** include `.env` or `/etc/nsa/gateway.env`.

```bash
nsa --version && nsa doctor
tail -20 ~/.nsa/audit.jsonl                                   # metadata only
# on the gateway host:
sudo journalctl -u nsa-gateway -u ollama --no-pager -n 80
systemctl is-active ollama nsa-gateway; ss -ltnp | grep -E ':(4000|11434)'
ollama list; df -h / | tail -1; free -h | head -2
```

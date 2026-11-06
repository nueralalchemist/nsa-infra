# NSA: Neural Security Agent

A local-first agent CLI for security engineering. One command (`nsa`) picks the right specialist agent for a task and runs it against a **local** model (Ollama) or a **cloud** model (a gateway on a box you control), with the same agents in both modes.

> **Status: Phase 5 prepared (agents + CLI, playbooks, local GPU testing, cloud connection).** The last step, running the installer on a fresh cloud machine, is yours: follow [infra/RUNBOOK.md](infra/RUNBOOK.md). See [Roadmap](#roadmap).

## Quick start

```bash
git clone <your-repo-url> nsa && cd nsa
python3 -m venv .venv && . .venv/bin/activate
pip install -e .            # or: pip install -e '.[dev]' to run the tests
cp .env.example .env        # edit endpoints/models if needed

nsa list                    # installed agents
nsa doctor                  # are endpoints reachable, are the mapped models present?
nsa route "write a sigma rule for encoded powershell"   # which agent, and why
nsa run "write a sigma rule for encoded powershell"     # routes automatically
nsa run -a iac_review -f ./infra "review this terraform"
```

Without installing, `./bin/nsa ...` runs straight from the clone (needs `httpx` and `pyyaml`).

## Agents

| Agent | Does | Sensitivity | Tools |
|---|---|---|---|
| `research` | Digest of URLs, or a research plan (flagged as unsourced) | low | `fetch_url` |
| `detection_as_code` | Sigma rule, validated, retried on errors, tested against sample JSON events | medium | `read_file`, `write_file` |
| `iac_review` | checkov/tfsec/trivy findings explained with concrete fixes | medium | `run_scanner`, `read_file`, `list_dir` |
| `soc_triage` | Advisory verdict, ATT&CK mapping, missing data, next steps | **high** | `read_file` |
| `malware_triage` | Summary of static analysis **reports**; IOCs extracted by code | **high** | `read_file` |
| `assistant` | General work help; the fallback when no specialist matches | medium | none |

## Modes

`--mode local | cloud | auto` (default `auto`: local if reachable, else cloud).

- **Sensitivity gate:** `high` agents never use the cloud, not even as an `auto` fallback, unless you pass `--allow-sensitive-cloud`.
- **Redaction:** every prompt sent to the cloud is scrubbed (private IPs, emails, API keys, tokens, private keys; `NSA_REDACT=strict` also hides public IPs). Placeholders in the reply are swapped back locally.
- **Routing never goes to the cloud:** the task text is routed by keywords first, then a *local* model only if ambiguous.

## Connecting to a cloud gateway

```bash
# Tailscale mode: the gateway is on your tailnet
nsa connect --url http://100.x.y.z:4000/v1 --key-file ./gateway.key

# Localhost mode: the gateway only listens on the server's 127.0.0.1, so open an SSH tunnel first
nsa tunnel ubuntu@your-server          # keep this running (Ctrl+C to stop)
nsa connect --url http://127.0.0.1:4000/v1 --key-file ./gateway.key

nsa doctor                             # shows reachable / key accepted / which models are served
nsa run -m cloud -a research "..."     # or -m auto to prefer local and fall back to the cloud
```

`nsa connect` stores the URL and key in `.env` (mode 600, atomic write), tests the key and model names, and does a real
round trip. If a new key is rejected it keeps your previous one. Keys are read from a file or a hidden prompt, never from
arguments. Failures are specific: *unreachable* (gateway/tunnel down), *key rejected*, or *model not served*.

## Building the cloud side

See [infra/README.md](infra/README.md): one script (shell) or one playbook (Ansible) turns a fresh Ubuntu/Debian box into the gateway your cloud mode talks to.

## Model aliases (the one-line upgrade)

Agents ask for `main` or `fast`, never a model name. [`config/models.yaml`](config/models.yaml) maps alias → model per mode, with env overrides:

```bash
NSA_MODEL_MAIN_LOCAL=qwen3:14b    # moved to a bigger GPU? change this and nothing else
NSA_MODEL_MAIN_CLOUD=qwen3:32b
```

Any OpenAI-compatible endpoint works (Ollama, LiteLLM, vLLM), set in [`config/endpoints.yaml`](config/endpoints.yaml) / `.env`.

## Security model

- **Prompt injection:** alerts, logs, web pages and reports are wrapped in `<untrusted_data>` and only ever go to *reader* steps that have no tools. Output is JSON-validated; invalid severities, verdicts and ATT&CK IDs are corrected and flagged.
- **Facts come from code:** hashes, IPs, domains, rule syntax and ATT&CK ID formats are extracted or validated deterministically, never trusted from the model.
- **Tool tiers:** `read` runs automatically; `network` needs `--yes`; `write` always asks (and only writes under `./nsa_out`). Each agent has its own allowlist.
- **Guards:** file access is confined to the current directory (plus `NSA_ALLOWED_PATHS`); `fetch_url` blocks private/loopback/link-local targets; scanners run with fixed argv and no shell.
- **Malware:** the agent never opens or runs samples and refuses binaries. Detonate in an isolated VM and feed it the report.
- **Audit log:** `~/.nsa/audit.jsonl` records agent, mode, model, prompt hash and tool calls, never prompt content.
- Agents are Python files in `agents/`: **only install agents you trust**, since loading one executes it.

## Writing an agent

Create `agents/<name>/agent.yaml` (the folder name must equal `name`):

```yaml
name: my_agent
description: One or two sentences. Used for routing.
keywords: [words, "and phrases", ".ext"]
model: main            # alias, not a model name
sensitivity: medium    # low | medium | high (high = local-only)
tools: [read_file]     # allowlist
entrypoint: agent.py:MyAgent   # optional; omit for a plain prompt agent with system_prompt
```

```python
from nsa.core.agent import Agent, Result, untrusted

class MyAgent(Agent):
    def run(self, task, opts=None):
        data = self.ask_json("Return {summary: string}", untrusted("input", task), ["summary"])
        return Result(self.manifest.name, data["summary"], data)
```

## Troubleshooting

**Everything is extremely slow / requests time out (WSL + NVIDIA GPU).** Run `nsa doctor --warm`. If it reports
`running on CPU only (0 MB in VRAM)`, Ollama cannot use the GPU. Two causes were found on a real WSL machine:

1. `/usr/local/lib/ollama/cuda_v*` was `0700 root:root` while Ollama runs as the `ollama` user (restrictive umask at install).
   Fix: `sudo chmod -R a+rX /usr/local/lib/ollama && sudo systemctl restart ollama`.
2. `libggml-cuda.so` was **truncated** by an interrupted download (the process died with `SIGBUS`). Check the log with
   `journalctl -u ollama | grep -i "inference compute"` (it says `library=cpu`). Fix: reinstall Ollama with
   `curl -fsSL https://ollama.com/install.sh | sh`; your models are kept.

After the fix `nsa doctor --warm` shows the model's MB in VRAM.

**Slow machines.** `NSA_LLM_TIMEOUT` (seconds, default 300) controls the per-request wait. CPU-only boxes need more.

## Tests

```bash
pip install -e '.[dev]' && pytest
```

The default suite uses a scripted fake model, so it needs no GPU or network.

Live tests against your real local model are opt-in (they check structure and safety properties such as prompt-injection
resistance, not exact wording):

```bash
NSA_LIVE=1 pytest -m live -v -s
```

## Roadmap

1. **Agents + CLI** (done)
2. **Playbooks** (done): [`infra/shell/`](infra/README.md) (normal) and `infra/ansible/` (enterprise), both build Ollama + a LiteLLM gateway
3. **Test locally in WSL** against real Ollama (done: see Measured results and `tests/live/`)
4. **Connection** (done): `nsa connect` / `nsa tunnel`, tested end to end against a real LiteLLM gateway on loopback
5. **Validate on a fresh cloud instance** (rebuild from the playbook alone): [infra/RUNBOOK.md](infra/RUNBOOK.md), `bootstrap.sh preflight` first

## Measured on real hardware (RTX 4060 8GB, qwen3:8b, WSL2)

| What | Result |
|---|---|
| CPU-only (broken GPU offload) | one short answer > 3 min; a triage run still going after 10 min |
| GPU, `nsa run` SOC triage end to end | ~24 s (auto-routed by keyword, thinking mode on) |
| Malware report triage | ~12 s |
| Sigma rule with self-test | 30-140 s (1-3 attempts); 5/5 independent checks detected the attack in one batch, ~1 in 6 missed overall |
| Cloud mode via a real LiteLLM gateway (loopback) | connect + round trip 2 s; secrets in a prompt crossed the wire only as `[[EMAIL_1]]`, `[[IP_1]]`, `[[SECRET_1]]`, `[[AWSKEY_1]]` (0 raw occurrences in the wire log) |
| Prompt injection inside an alert | verdict never flipped (6/6 runs); IOCs always extracted by code |
| `main` thinking vs `/no_think` | thinking: 20 s, valid JSON 3/3, stable verdict. `/no_think`: 29 s, one run missing the verdict. **Thinking stays on for `main`.** |

## Known limitations

- Quality depends on the model; an 8B model needs the structured, bounded steps used here and will still make mistakes. Treat all output as advisory.
- ATT&CK technique IDs from the model are format-checked only, and are often wrong or too generic. They are labelled
  "model-suggested; verify" in the output. The model also misjudged an IP range (called a documentation range "private").
- `detection_as_code` validates syntax and self-tests the rule against model-written sample events, but a rule can still
  miss real-world variants. Treat it as a first draft and run it against your own log data.
- Qwen3 "thinking" is on for `main` (measured better) and off for `fast` (routing/classification).
- No license file yet: add one before publishing.

# NSA: Neural Security Agent

**A local-first command-line toolkit of security agents.** One command (`nsa`) picks the right specialist for your task (SOC alert triage, Sigma rule writing, IaC review, malware-report triage, research) and runs it against a model on **your own machine**, or optionally against a disposable cloud box you can rebuild with one script. The same agents work in both places.

It is built around one idea: small local models are good at *narrow, structured steps* and bad at open-ended planning. So every agent is a fixed pipeline where the model fills bounded steps and **code does everything that must be exact or safe**.

```
 you ── nsa ──▶ router ──▶ agent (fixed pipeline) ──▶ tools (read / network / write tiers)
                              │
                              ▼
                        LLM client ──▶ local Ollama (your GPU)          ← default, sensitive data stays here
                              │
                              └─▶ [redacted] ─▶ tunnel/tailnet ─▶ LiteLLM gateway ─▶ Ollama   ← optional cloud box
```

## Highlights

- **Local-first, cloud-optional.** `--mode local | cloud | auto`. Sensitive agents (`soc_triage`, `malware_triage`) are local-only by policy; `auto` never falls back to the cloud for them.
- **Safe by construction.** Alerts, logs and web pages are treated as untrusted: they only ever reach a *reader* step with no tools. IOCs, hashes and rule syntax come from code, not the model. A hidden "mark this benign" instruction in an alert did not change the verdict in live tests.
- **Redaction on the wire.** Cloud prompts have emails, private IPs, keys, tokens and passwords swapped for placeholders and restored locally on the reply. Checked with a logging proxy: zero raw secrets crossed the network.
- **Swap the model in one line.** Agents ask for an alias (`main`, `fast`); `config/models.yaml` maps it to a real model per mode.
- **Disposable cloud side.** A shell script (or Ansible playbook) turns a fresh Debian/Ubuntu machine into a hardened Ollama + LiteLLM gateway: **66 seconds** on a real machine, idempotent, survives reboots.
- **Honest about its limits.** Output is advisory and labelled. [What is and isn't verified](docs/TESTING.md#4-infrastructure-verification-matrix) is written down.

## Quick start (local)

Requires Python 3.10+, [Ollama](https://ollama.com), and a model.

```bash
git clone <your-repo-url> nsa && cd nsa
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
cp .env.example .env
ollama pull qwen3:8b

nsa doctor --warm                              # endpoints, model names, GPU offload
nsa run "write a sigma rule for encoded powershell"
```

Everything below works from this point. `./bin/nsa ...` runs without installing (needs `httpx`, `pyyaml`).

## The agents

| Agent | What it does | Runs where |
|---|---|---|
| `soc_triage` | Advisory verdict, severity, ATT&CK suggestions, next steps for an alert; IOCs extracted by code | local only |
| `malware_triage` | Triage from static-analysis **reports** (capa, strings, sandbox); refuses binaries; never executes anything | local only |
| `detection_as_code` | Sigma rule, strictly parsed, validated, and **self-tested** against generated malicious/benign events; optional test on your own logs | local or cloud |
| `iac_review` | Runs checkov/tfsec/trivy if installed and explains findings with concrete fixes | local or cloud |
| `research` | Digest of URLs (SSRF-guarded fetch) or a clearly-labelled research plan | local or cloud |
| `assistant` | General help; the fallback when nothing else matches | local or cloud |

```bash
nsa list                                         # what's installed
nsa route "triage this suspicious login alert"   # which agent, and why (no model call)
nsa run -a soc_triage -f alert.json "triage this alert"
nsa run -a iac_review -f ./infra "review this terraform"
nsa run -a malware_triage -f capa.txt "triage this report"
```

Details, pipelines, limits and how to **write your own agent**: [docs/AGENTS.md](docs/AGENTS.md).

## Adding a cloud gateway (optional)

```bash
# on a fresh Debian/Ubuntu machine, from the files in infra/
./shell/bootstrap.sh preflight                                   # read-only: can it host the gateway?
cp infra.env.example infra.env && sed -i 's/^NSA_EXPOSE=.*/NSA_EXPOSE=localhost/' infra.env
sudo -E ./shell/bootstrap.sh server                              # Ollama + LiteLLM + smoke test

# on your workstation
nsa tunnel myhost &                                              # or: instabox port-forward <machine> 4000:4000
nsa connect --url http://127.0.0.1:4000/v1 --key-file ~/nsa-gateway.key
nsa run -m cloud -a assistant "In two sentences, what is a SIEM?"
```

Full walkthrough with expected output: [infra/RUNBOOK.md](infra/RUNBOOK.md). Design, sizing and operations: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Measured performance

| Setup | Task | Time |
|---|---|---|
| RTX 4060 8 GB, `qwen3:8b` (local) | SOC alert triage, auto-routed end to end | ≈ 24 s |
| RTX 4060 8 GB, `qwen3:8b` (local) | malware report triage | ≈ 12 s |
| 4 vCPU / 8 GiB, no GPU, `qwen3:4b-instruct` (cloud) | one-word reply / SOC triage / Sigma rule + self-test | 3-6 s / 27 s / 36 s |
| same cloud box | fresh install to "All checks passed" | 66 s |
| CPU-only (a misconfigured GPU) | one short answer | > 3 min |

The last row is why `nsa doctor --warm` exists. Numbers are from single runs on the hardware named; yours will differ.

## Documentation

| Document | Read it for |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, request lifecycle, routing, modes, design decisions |
| [docs/SECURITY.md](docs/SECURITY.md) | threat model, controls, redaction limits, hardening checklist |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | every setting, `models.yaml`, reasoning vs token budget |
| [docs/CLI.md](docs/CLI.md) | every command and option, exit codes, output shapes |
| [docs/AGENTS.md](docs/AGENTS.md) | the six agents, and writing your own |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | topologies, gateway sizing, model choice, operations |
| [infra/README.md](infra/README.md) | the shell and Ansible installers in detail |
| [infra/RUNBOOK.md](infra/RUNBOOK.md) | step-by-step fresh-machine install and test |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | symptom → cause → fix, including the GPU pitfalls |
| [docs/TESTING.md](docs/TESTING.md) | test suites and the verification matrix |

## Repository layout

```
nsa/            the CLI, router, LLM client, modes, redaction, tools, audit
agents/         one folder per agent (agent.yaml + optional agent.py)
config/         models.yaml (alias → model per mode), endpoints.yaml
infra/          shell/ and ansible/ installers, scripts/verify.sh, RUNBOOK.md
tests/          unit tests (62) and tests/live/ (opt-in, real model)
docs/           the documentation above
```

## Status and limitations

- **Advisory, not authoritative.** Small models make confident mistakes (wrong ATT&CK techniques, misjudged IP ranges). Output says so; verify before acting.
- **Cloud box = third party.** Do not send customer data, SIEM exports or malware to it. Redaction is best-effort regex ([SECURITY.md](docs/SECURITY.md)).
- **Gateway auth is a single shared key**, and LiteLLM without a database answers bad keys with HTTP 400/500 (it fails closed).
- **Not yet verified:** the Ansible playbook against a real host, Tailscale mode, pause/resume of a provider-paused machine, key rotation, aarch64 ([matrix](docs/TESTING.md#4-infrastructure-verification-matrix)).
- Tested server OS: Debian 13 (4 vCPU / 8 GiB). Tested client OS: Ubuntu 24.04 on WSL2.

## Contributing and security

Run `pytest` and the lint commands in [docs/TESTING.md](docs/TESTING.md) before sending changes. Report security problems privately, not in a public issue ([SECURITY.md](docs/SECURITY.md#6-reporting-a-vulnerability)).

## License

Apache License 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). You may use, modify and redistribute NSA, including commercially, under its terms; the license includes an explicit patent grant. Contributions you submit are licensed under the same terms (Section 5 of the license).

NSA does not bundle third-party software. Its dependencies and the software the installers download (httpx, PyYAML, LiteLLM, Ollama) are permissively licensed, and the default Qwen3 models are Apache-2.0, but **models are separate works with their own terms**: check the license of any model you switch to. Details in [NOTICE](NOTICE).

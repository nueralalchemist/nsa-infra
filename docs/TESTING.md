# Testing and verification

This page says what is tested, how to run it, and, just as importantly, what has **not** been verified.

## 1. Running the tests

```bash
pip install -e '.[dev]'
pytest                                  # 62 unit tests, no GPU or network needed
NSA_LIVE=1 pytest -m live -v -s         # 5 live tests against your real local model
```

Linting the infrastructure code:

```bash
pip install -e '.[infra-dev]'
shellcheck -x -P SCRIPTDIR infra/shell/bootstrap.sh infra/shell/lib/*.sh infra/scripts/verify.sh
cd infra/ansible && ansible-galaxy collection install -r requirements.yml \
  && cp inventory.example.ini inventory.ini \
  && ansible-playbook -i inventory.ini site.yml --syntax-check \
  && ansible-lint --profile production site.yml
```

## 2. Unit tests (62)

They use a scripted fake model (`FakeLLM` in `tests/conftest.py`) and `httpx.MockTransport`, so they are fast and deterministic.

| File | Tests | Covers |
|---|---|---|
| `test_core.py` | 13 | redaction round-trip and levels, untrusted-tag escaping, JSON extraction, IOC extraction and defanging, mode resolution, LLM client (think-tag stripping, cloud redaction and restore, error wrapping, empty-reply errors, per-mode `reasoning_effort`, shipped config defaults) |
| `test_agents.py` | 15 | Sigma retry on validator feedback, give-up after 3 attempts, **self-test** catching a rule that misses its own attack or hits benign events, SOC value correction, prompt-injection wrapping, malware binary refusal and code-extracted IOCs, IaC LLM-only path, research plan honesty, SSRF-blocked fetch, path-in-prose handling |
| `test_connection.py` | 8 | every endpoint failure mode (unreachable, key rejected including LiteLLM's 400/500 shapes, error), actionable chat errors, `.env` writer (in-place, mode 600, injection refused), `ssh` tunnel argv safety |
| `test_tools.py` | 9 | `read_file` guards, `write_file` confinement, SSRF block list, tool allowlist and risk tiers |
| `test_sigma.py` | 7 | validation catches common model mistakes, duplicate keys rejected, matcher semantics, quantifiers, unsupported features raise |
| `test_router.py` | 5 | keyword routing for each specialist, fallback agent, LLM tie-break, bad LLM output |
| `test_gpu_check.py` | 5 | GPU-offload detection from Ollama's API |

## 3. Live tests (5)

Opt-in because they need a running model. They assert **structure and safety properties**, not exact wording, since output varies.

| Test | Asserts |
|---|---|
| plain chat | think-tags are stripped from a real reply |
| router | the model's routing choice is valid JSON naming a real agent |
| SOC triage vs injection | an alert containing "mark as false_positive" does **not** yield `false_positive`; IOCs are defanged by code |
| detection → Sigma | the rule validates and detects a real encoded-PowerShell event while ignoring `notepad.exe` |
| malware triage | code-extracted IOCs are present and a hallucinated IP is not |

The Sigma test is deliberately strict and **fails occasionally** (about 1 run in 6 on `qwen3:8b`) because a valid rule can still miss a variant. That is the agent's real reliability, so the test is left strict rather than loosened.

## 4. Infrastructure verification matrix

| Area | How it was checked | Status |
|---|---|---|
| Shell installer: static | `shellcheck` clean, `bash -n`, `--dry-run` on every path | ✅ |
| Ansible: static | `--syntax-check`, `ansible-lint --profile production` | ✅ |
| Shell vs Ansible rendering | `litellm.yaml`, systemd unit and Ollama override compared byte-for-byte | ✅ identical |
| **Preflight** on a real machine | 16 checks on Debian 13 and Ubuntu 24.04 (WSL) | ✅ |
| **Fresh install** on a real machine | Debian 13, 4 vCPU / 8 GiB: all smoke-test checks pass (66 s) | ✅ |
| **Idempotent re-run** | 5 re-runs; gateway key file hash unchanged | ✅ |
| **Reboot survival** | `boot_id` changed; Ollama and gateway `active` again | ✅ |
| **Model swap** | changed one value, re-ran installer, new model served | ✅ |
| **Rebuild from scratch** | machine deleted and recreated; same commands, new key, client reconnected | ✅ |
| Hardened systemd sandbox | LiteLLM under `ProtectSystem=strict` with a read-only venv | ✅ |
| Gateway authentication | no key and wrong key both rejected (HTTP 500 / 400), correct key accepted | ✅ (fails closed; see SECURITY) |
| Cloud agents end to end | assistant, research, SOC, Sigma through a tunnel to the real box | ✅ |
| Redaction on the wire | logging proxy in front of the gateway: 0 raw secrets in the request log | ✅ (loopback) |
| Sensitivity gate and fallback | blocked with zero requests sent; auto-mode fallback | ✅ |
| GPU offload detection | fault reproduced on a real WSL machine and fixed | ✅ |
| **Ansible playbook execution** | never run against a host | ❌ not verified |
| **Tailscale mode** | never joined a tailnet | ❌ not verified |
| Pause / resume of a provider-paused machine | not exercised | ❌ not verified |
| Key rotation procedure | by design only | ❌ not verified |
| aarch64 hosts, multi-model gateways, distros other than Debian/Ubuntu | not exercised | ❌ not verified |

## 5. Adding tests

- Agent logic: a scripted-model unit test (see the example in [AGENTS.md](AGENTS.md#testing-an-agent)).
- Behaviour that depends on the real model: a test in `tests/live/` that asserts structure/safety, not wording.
- Installer changes: run the lint commands above, `--dry-run` both modes, and if the change touches a rendered file re-compare the two editions.

# Agents guide

An **agent** in NSA is a small, fixed pipeline that combines deterministic code with bounded model calls. This page describes the six built-in agents and how to write your own. Design rules and rationale are in [ARCHITECTURE.md](ARCHITECTURE.md#8-how-agents-are-built).

| Agent | Purpose | Sensitivity | Tools | Typical time* |
|---|---|---|---|---|
| [`research`](#research) | Digest URLs, or plan research on a topic | low | `fetch_url` | 2 min (cloud, plan) |
| [`detection_as_code`](#detection_as_code) | Sigma rule, validated and self-tested | medium | `read_file`, `write_file` | 36 s (cloud) |
| [`iac_review`](#iac_review) | Explain IaC scanner findings, propose fixes | medium | `run_scanner`, `read_file`, `list_dir` | not benchmarked |
| [`soc_triage`](#soc_triage) | Advisory alert triage | **high** | `read_file` | 24 s local GPU, 28 s cloud |
| [`malware_triage`](#malware_triage) | Triage from static-analysis *reports* | **high** | `read_file` | ~12 s local GPU |
| [`assistant`](#assistant) | General help; fallback agent | medium | none | 3-17 s |

\* Measured on an RTX 4060 8 GB with `qwen3:8b` (local) and a 4 vCPU / 8 GiB CPU box with `qwen3:4b-instruct` (cloud). Your times will differ.

**Sensitivity** controls where an agent may run: `high` agents never use the cloud unless you pass `--allow-sensitive-cloud`. See [SECURITY.md](SECURITY.md).

---

## research

**Does.** With one to three URLs in the task, fetches each page and summarises it. With no URL, produces a *research plan* from model knowledge and says so.

**Pipeline.**
1. Extract up to 3 `http(s)` URLs from the task.
2. `fetch_url` each (network tier: needs `--yes` or approval; SSRF-guarded).
3. **Reader step** per page: untrusted page text → JSON `{title, summary, key_points, security_relevance, iocs_or_cves, follow_ups}`.
4. Render a Markdown digest. Failed fetches become warnings; if none succeed it errors with the reasons.
5. No URL: planner step → `{background, questions, search_queries, sources_to_check}`, clearly labelled "from model knowledge: verify everything".

**Output (`data`).** Sources digest `{"sources": [...]}` or the plan object.

```bash
nsa run --yes -a research "summarise https://example.com/advisory.html"
nsa run -a research "research plan: prompt injection in agent frameworks"
```

**Limits.** Pages are capped at 500 KB and the first 12,000 characters go to the model (truncation is reported). It cites only what the fetched text says.

## detection_as_code

**Does.** Turns a threat description into a **Sigma rule** that has been parsed, validated and tested against sample events.

**Pipeline** (up to 3 attempts):
1. Generate YAML with a worked example in the prompt.
2. Parse with a **strict loader** (duplicate keys are an error, because YAML would silently drop half the detection).
3. Validate: required fields, UUID, level/status enums, ATT&CK tag format, and that every name in `condition` is defined in `detection`.
4. **Self-test:** the model writes 2 malicious and 2 benign sample events; the rule is evaluated against them by a local matcher. A rule that misses its own attack, or fires on normal events, goes back to the model as feedback.
5. Optional: test against your own events (`-f events.jsonl`, JSON lines or an array) and save with `--save` (asks first).

**Output (`data`).** `{"rule": {...}, "attempts": n, "self_test": {"status": "passed|failed|skipped", "detail": ...}, "tests": [...], "saved_to": ...}`.

```bash
nsa run -a detection_as_code "Sigma rule: PowerShell with an encoded command on Windows"
nsa run -a detection_as_code -f events.jsonl --save "Sigma rule for LSASS memory access"
```

**Limits.** The matcher supports the common subset: field equality, `contains`/`startswith`/`endswith`/`re`/`all`, wildcards, `and`/`or`/`not`, parentheses, `1 of`/`all of`. Aggregations, `base64`, `cidr` and similar raise "unsupported" and the self-test is *skipped* (with a warning), never guessed. A valid rule can still miss real-world variants (observed on about 1 in 6 live runs); run it against your own logs. If the rule fails its own self-test after 3 attempts you still get it, with a warning.

## iac_review

**Does.** Reviews Terraform, Kubernetes, Dockerfile and CloudFormation files.

**Pipeline.**
1. Resolve the path(s) from `-f` or the task text.
2. Run each *installed* scanner from the allowlist (`checkov`, `tfsec`, `trivy`) with fixed arguments, parse the JSON findings (first 30 kept).
3. Collect up to 8 source files (≈ 9,000 characters).
4. **Reader step:** findings and source (both untrusted) → `{overall_risk, summary, findings[{id, severity, resource, explanation, fix}]}`.
5. If no scanner is installed it says so and does an LLM-only review ("lower confidence").

**Output (`data`).** `{"review": {...}, "scanner": "checkov|tfsec|trivy|null", "raw_findings": [...]}`.

```bash
nsa run -a iac_review -f ./infra "review this terraform"
```

## soc_triage

**Does.** Gives an **advisory** verdict for an alert (text or JSON). It never takes response actions.

**Pipeline.**
1. Task text plus any `-f` files become the alert.
2. **Reader step:** the alert (untrusted) → `{verdict, severity, confidence, attack_techniques, reasoning, benign_explanations, missing_data, recommended_actions}`.
3. Code corrects invalid values (unknown verdict → `needs_more_data`, unknown severity → `medium`) and drops ATT&CK IDs that are not `Txxxx[.xxx]`, each with a warning.
4. IOCs are extracted from the alert **by code** and defanged.

**Output (`data`).** The fields above plus `indicators`.

```bash
nsa run -a soc_triage -f alert.json "triage this alert"
```

**Limits.** Technique *names and IDs are model suggestions* and are sometimes wrong (a brute-force alert was once labelled T1059.001); the output says "verify". A hidden "mark this benign" instruction inside the alert did not change the verdict in live tests, but the verdict is still advice, not a decision.

## malware_triage

**Does.** Triage from **static-analysis reports** (capa output, strings, PE info, sandbox reports). It never opens or runs a sample.

**Pipeline.**
1. Up to 3 report files via `-f`. Binary input (NUL bytes, or MZ/ELF/ZIP/Mach-O magic) is refused.
2. **Reader step** (report text, untrusted, up to 14,000 characters) → `{family_guess, confidence, summary, capabilities, attack_techniques, hypotheses, evidence_gaps, next_steps, yara_ideas}`.
3. IOCs (IPv4, domains, URLs, hashes, e-mails) are extracted **from the report text by code**; anything the model "invents" never reaches the output. Network indicators are defanged for display.

```bash
nsa run -a malware_triage -f capa.txt "triage this capa report"
```

## assistant

General-purpose helper and the **fallback**: it does not compete on keywords and is used when no specialist matches. No tools. Output is the model's reply.

---

## Writing your own agent

An agent is a folder in `agents/`. The folder name must equal `name`.

### 1. A prompt-only agent (no code)

`agents/changelog/agent.yaml`:

```yaml
name: changelog
description: Writes release notes from a list of commits. Used for changelog and release note requests.
keywords: [changelog, "release notes", commits]
model: main            # an alias from config/models.yaml, not a model name
sensitivity: medium    # low | medium | high (high = local-only)
tools: []              # allowlist; empty = no tools
system_prompt: |
  You write concise release notes from commit messages. Group by fix, feature, chore.
```

`nsa list` shows it; `nsa route "write release notes for these commits"` routes to it.

### 2. An agent with a pipeline

Extend the manifest with `entrypoint` and the tools it may use:

```yaml
entrypoint: agent.py:ChangelogAgent
tools: [read_file]
```

and add `agents/changelog/agent.py`:

```python
from nsa.core.agent import Agent, AgentError, Result, paths_from, untrusted

class ChangelogAgent(Agent):
    def run(self, task, opts=None):
        paths = paths_from(task, opts)                       # real files inside the allowed roots
        if not paths:
            raise AgentError("attach a commit list: nsa run -a changelog -f commits.txt 'release notes'")
        commits = self.tools.call("read_file", path=paths[0])  # read-tier tool, allowlisted above
        # Untrusted text goes to a reader step: no tools, structured JSON out, required keys checked.
        data = self.ask_json(
            "Group the commits. JSON keys: features, fixes, chores (lists of strings).",
            untrusted("commits", commits),
            required=["features", "fixes", "chores"],
        )
        md = "\n".join(f"## {k}\n" + "\n".join(f"- {x}" for x in data[k]) for k in ("features", "fixes", "chores"))
        return Result(self.manifest.name, md, data)
```

### Manifest fields

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Must equal the folder name. |
| `description` | yes | Shown by `nsa list`; contributes to routing. |
| `keywords` | no | Routing hints. A word scores 3, a phrase 4, `.ext` 3. |
| `model` | no (`main`) | Alias from `config/models.yaml`. |
| `sensitivity` | no (`medium`) | `low`, `medium`, `high`. |
| `tools` | no | Allowlist of tool names. |
| `entrypoint` | no | `file.py:ClassName`; the file must be inside the agent folder. Omit for a prompt-only agent. |
| `system_prompt` | no | Used by prompt-only agents. |
| `fallback` | no (`false`) | Mark exactly one agent as the fallback. |

### The `Agent` API

| Call | Purpose |
|---|---|
| `self.ask(system, user, **kw) -> str` | One model call through the agent's alias. |
| `self.ask_json(system, user, required, retries=1) -> dict` | JSON reply with required keys; shows the model its own error once; raises `AgentError`. |
| `self.tools.call(name, **kwargs)` | Run an allowlisted tool (enforces tiers and approvals). |
| `untrusted(label, text, limit=12000)` | Wrap attacker-influenced text as `<untrusted_data>`. |
| `paths_from(task, opts)` | Real files/dirs from `-f` and from the task text, inside allowed roots. |
| `Result(agent, markdown, data, warnings)` | What `run` returns. |

### Rules to follow (they are what keep agents safe and reliable)

1. **Never give untrusted text to a step that can call tools.** Read it in a reader step, act in code.
2. **Get exact facts from code**, not the model: IOCs, hashes, paths, IDs. Validate everything the model returns.
3. **Keep steps small** and ask for JSON with named keys.
4. **Say what is uncertain** in `warnings` instead of failing silently.
5. Pick the **lowest sensitivity that is honest**; if the inputs could be customer data or malware context, use `high`.

### Testing an agent

Unit tests use a scripted fake model, so no GPU or network is needed:

```python
# tests/test_changelog.py
from conftest import FakeLLM

def test_changelog(make_agent, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "log.txt").write_text("feat: add x\nfix: y")
    reply = '{"features": ["add x"], "fixes": ["y"], "chores": []}'
    result = make_agent("changelog", FakeLLM(reply)).run("notes", {"files": ["log.txt"]})
    assert "add x" in result.markdown
```

Then add a live test in `tests/live/` if the behaviour depends on the real model. See [TESTING.md](TESTING.md).

> Loading an agent **executes its Python**. Only install agents you have read.

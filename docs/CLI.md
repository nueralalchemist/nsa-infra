# Command-line reference

```
nsa [--version] <command> [options]

commands:  list   doctor   connect   tunnel   route   run
```

Results go to **stdout**; routing, mode, warnings and errors go to **stderr**, so `nsa run ... > report.md` captures only the result.

Run from the repository (`./bin/nsa ...`) or, after `pip install -e .`, as `nsa`.

## `nsa run`

Run a task. The agent is chosen automatically unless you force one.

```
nsa run [-a AGENT] [-m {local,cloud,auto}] [-f FILE]... [--yes] [--save]
        [--json] [-o OUT] [--dry-run] [--allow-sensitive-cloud]  TASK...
```

| Option | Meaning |
|---|---|
| `TASK` | The task text. Use `-` to read it from stdin. |
| `-a, --agent NAME` | Skip routing and use this agent (see `nsa list`). |
| `-m, --mode` | `local`, `cloud`, or `auto` (default). `auto` prefers local, falls back to cloud when allowed. |
| `-f, --file PATH` | Attach a file or directory. Repeatable. Must be inside the current directory or `NSA_ALLOWED_PATHS`. |
| `--yes` | Pre-approve **network** tools (e.g. `fetch_url`) for this run. Never approves write tools. |
| `--save` | Let the agent write artifacts to `./nsa_out` (still asks first). Used by `detection_as_code`. |
| `--json` | Print `{"agent", "data", "warnings"}` instead of Markdown. |
| `-o, --out FILE` | Write the result to a file instead of stdout. |
| `--dry-run` | Print the chosen agent, mode and model, then stop. No model call. |
| `--allow-sensitive-cloud` | Allow a `high`-sensitivity agent to use the cloud (prompts are still redacted). |

```bash
nsa run "write a sigma rule for encoded powershell"            # auto-routed
nsa run -a soc_triage -f alert.json "triage this alert"        # forced, local-only by policy
nsa run -m cloud -a research "research plan: LLM agent injection"
nsa run -a iac_review -f ./infra "review this terraform"
echo "summarise this" | nsa run -a assistant -                 # task from stdin
nsa run --dry-run "analyse this capa output from a dropper"    # see the decision only
```

**Approvals.** `read` tools run automatically. A `network` tool needs `--yes` or an interactive "y". A `write` tool always needs an interactive "y"; with no terminal it is denied.

## `nsa route`

```
nsa route TASK...
```

Prints which agent a task would go to, the confidence, the method (`keyword`, `llm` or `fallback`), the reason, and every agent's score. Runs no agent.

## `nsa list`

Lists installed agents with their sensitivity and a one-line description.

## `nsa doctor`

```
nsa doctor [--warm]
```

For each endpoint: reachable? key accepted? And for each alias, is the mapped model actually served (`ok` / `NOT FOUND on endpoint`)? Failure reasons are specific: `UNREACHABLE`, `AUTH FAILED`, or another HTTP error. On a local Ollama it also reports GPU offload.

`--warm` first loads the main local model so offload can be inspected. If the model sits in system RAM despite an NVIDIA GPU you get a warning and a fix; see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#ollama-is-using-the-cpu-instead-of-the-gpu).

Exit status is `1` when the local endpoint is unreachable, a configured model is missing on either endpoint, or the CPU-only GPU warning applies. An unreachable *cloud* endpoint is reported but does not fail the command.

## `nsa connect`

Point `nsa` at a cloud gateway and prove it works.

```
nsa connect --url URL [--key-file FILE] [--no-test]
```

1. Normalises the URL (adds `/v1`), warns about plain `http` to a non-local, non-tailnet address.
2. Reads the key from `--key-file` or a hidden prompt (Enter keeps the existing key). **Keys are never accepted as arguments.**
3. Writes `NSA_CLOUD_URL` / `NSA_CLOUD_KEY` to `.env` (mode 600, atomic). If a new key is **rejected**, your previous key is restored.
4. Checks the endpoint and that the configured cloud model names are served.
5. Unless `--no-test`, does a real round trip with the `fast` alias and prints the latency.

## `nsa tunnel`

Open an SSH tunnel for a gateway that listens only on the server's `127.0.0.1` (`NSA_EXPOSE=localhost`).

```
nsa tunnel [--port 4000] [-i IDENTITY] [--dry-run] TARGET
```

Runs `ssh -N -L 127.0.0.1:PORT:127.0.0.1:PORT -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 ... -- TARGET` in the foreground (Ctrl+C closes it). `TARGET` is `user@host` or an `~/.ssh/config` alias; anything that could be read as an ssh option is rejected. Use an alias when the server needs a custom port or key.

Providers that ship their own port-forward command can be used instead; all that matters is that the gateway's port appears on `127.0.0.1:4000` locally.

## Exit status

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Handled error: mode not allowed, endpoint/key problem, agent could not produce a valid result, tool denied or failed, `doctor` found a problem. The message is on stderr (`error: ...`). |
| `2` | Usage error (bad option, empty task, unknown agent) |
| `130` | Interrupted (Ctrl+C) |

## Output shape (`--json`)

```json
{
  "agent": "soc_triage",
  "data":  { "verdict": "suspicious", "severity": "medium", "attack_techniques": [...], "indicators": {...} },
  "warnings": ["dropped ATT&CK technique IDs with invalid format"]
}
```

`data` is agent-specific; see [AGENTS.md](AGENTS.md).

## Files `nsa` reads and writes

| Path | When |
|---|---|
| `.env`, `config/*.yaml` | read at start-up |
| `.env` | written by `nsa connect` |
| `~/.nsa/audit.jsonl` | appended on every run, model call and tool call (metadata only) |
| `./nsa_out/` | written only by an approved `write_file` |

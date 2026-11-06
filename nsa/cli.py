"""The `nsa` command."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from nsa import __version__
from nsa.core.agent import AgentError
from nsa.core.audit import Audit
from nsa.core.config import load_dotenv, load_yaml, set_env_values
from nsa.core.llm import (Endpoint, LLMClient, LLMError, check_endpoint, cpu_only_models, ollama_loaded_models,
                          ollama_warm, probe)
from nsa.core.modes import MODES, ModeError, load_endpoints, resolve_mode
from nsa.core.registry import RegistryError, agent_class, discover
from nsa.core.tools import ToolDenied, ToolError, ToolRunner
from nsa.router import route


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _make_approver(yes: bool):
    def approve(tool, args: dict) -> bool:
        if tool.risk == "network" and yes:
            return True
        if not sys.stdin.isatty():
            return False
        shown = {k: (f"<{len(v)} chars>" if k == "content" else str(v)[:100]) for k, v in args.items()}
        return input(f"[approve] {tool.name} ({tool.risk}) {shown} ? [y/N] ").strip().lower() in ("y", "yes")

    return approve


def _routing_llm(endpoints, models, audit):
    """Routing only ever uses the local endpoint."""
    if probe(endpoints["local"]):
        return LLMClient(endpoints["local"], models, audit=audit, agent="router")
    return None


def _read_task(args) -> str:
    if args.task == ["-"]:
        return sys.stdin.read().strip()
    return " ".join(args.task).strip()


def cmd_list(args, manifests) -> int:
    for m in manifests.values():
        first_sentence = m.description.split(". ")[0].rstrip(".")
        print(f"{m.name:<20} [{m.sensitivity:<6}] {first_sentence}")
    return 0


def _alias_report(mode: str, models: dict, available: set[str]) -> bool:
    ok = True
    for alias, mapping in models.get("aliases", {}).items():
        name = mapping.get(mode, "")
        present = name in available or f"{name}:latest" in available
        print(f"           {alias:<5} -> {name:<24} {'ok' if present else 'NOT FOUND on endpoint'}")
        ok = ok and present
    return ok


_HINTS = {
    "unreachable": "Is the gateway running and the tailnet/SSH tunnel up? (tunnel mode: `nsa tunnel user@host`)",
    "auth_failed": "Wrong or missing API key: `nsa connect --url <url>` to set it again.",
}


def cmd_doctor(args, manifests) -> int:
    endpoints, models = load_endpoints(), load_yaml("models.yaml")
    ok = True
    print(f"nsa {__version__}   agents: {len(manifests)}")
    for mode, ep in endpoints.items():
        status = check_endpoint(ep)
        if status.state == "unconfigured":
            print(f"  {mode:<6} not configured" + ("  (set NSA_CLOUD_URL or run `nsa connect`)" if mode == "cloud" else ""))
            continue
        if status.state != "ok":
            print(f"  {mode:<6} {ep.base_url}  {status.state.upper().replace('_', ' ')}: {status.detail}")
            if status.state in _HINTS:
                print(f"           {_HINTS[status.state]}")
            ok = ok and mode != "local"
            continue
        auth = ", key accepted" if mode == "cloud" else ""
        print(f"  {mode:<6} {ep.base_url}  reachable{auth}, {len(status.models)} models")
        ok = _alias_report(mode, models, set(status.models)) and ok
        if mode == "local":
            ok = _check_gpu(ep, models, args.warm) and ok
    return 0 if ok else 1


def _check_gpu(ep, models: dict, warm: bool) -> bool:
    """Warn when a local Ollama model sits entirely in CPU RAM although an NVIDIA GPU is present."""
    if warm:
        alias = models.get("aliases", {}).get("main", {})
        if alias.get("local"):
            print(f"           loading {alias['local']} to inspect GPU offload (can take a moment)...")
            ollama_warm(ep, alias["local"])
    loaded = ollama_loaded_models(ep)
    if loaded is None:
        return True  # not Ollama, nothing to check
    if not loaded:
        print("           gpu: no model loaded yet (run `nsa doctor --warm` to check GPU offload)")
        return True
    cpu_only = cpu_only_models(loaded)
    if cpu_only and shutil.which("nvidia-smi"):
        print(f"           gpu: WARNING {', '.join(cpu_only)} is running on CPU only (0 MB in VRAM) but an NVIDIA GPU exists.")
        print("                Typical WSL cause: the Ollama CUDA dir is unreadable by the 'ollama' user.")
        print("                Check: ls -ld /usr/local/lib/ollama/cuda_v*   Fix: sudo chmod -R a+rX /usr/local/lib/ollama"
              " && sudo systemctl restart ollama")
        return False
    print("           gpu: " + ", ".join(f"{m['name']} {m['size_vram'] // 2**20} MB in VRAM" for m in loaded))
    return True


_URL_RE = re.compile(r"^https?://[A-Za-z0-9._\-]+(:\d{1,5})?(/[A-Za-z0-9._~/\-]*)?$")


def cmd_connect(args, manifests) -> int:
    """Point nsa at a cloud gateway, then prove the connection end to end."""
    url = args.url.rstrip("/")
    if not _URL_RE.match(url):
        raise ModeError(f"invalid gateway URL: {args.url!r}")
    if not url.endswith("/v1"):
        url += "/v1"
        _err(f"[connect] using {url} (the gateway serves the OpenAI API under /v1)")
    if args.url.startswith("http://") and not re.match(r"^http://(127\.|localhost|100\.|\[::1\])", args.url):
        _err("[warn] plain http to a non-local, non-tailnet address: the key and prompts would travel unencrypted.")

    key = ""
    if args.key_file:
        key = Path(args.key_file).read_text(encoding="utf-8").strip()
    elif sys.stdin.isatty():
        key = getpass.getpass("Gateway API key (Enter to keep the existing one): ").strip()
    updates = {"NSA_CLOUD_URL": url}
    if key:
        updates["NSA_CLOUD_KEY"] = key
    previous = {k: os.environ[k] for k in updates if os.environ.get(k)}  # to roll back a rejected key
    path = set_env_values(updates)
    os.environ["NSA_CLOUD_URL"] = url
    if key:
        os.environ["NSA_CLOUD_KEY"] = key
    print(f"saved to {path} (mode 600)")

    ep = load_endpoints()["cloud"]
    status = check_endpoint(ep, timeout=10)
    if status.state != "ok":
        print(f"cloud {status.state.upper().replace('_', ' ')}: {status.detail}")
        print(_HINTS.get(status.state, ""))
        if status.state == "auth_failed" and key and previous.get("NSA_CLOUD_KEY"):
            set_env_values({"NSA_CLOUD_KEY": previous["NSA_CLOUD_KEY"]})
            print("The new key was rejected, so your previous key was kept.")
        return 1
    models = load_yaml("models.yaml")
    ok = _alias_report("cloud", models, set(status.models))
    if args.no_test or not ok:
        return 0 if ok else 1
    llm = LLMClient(ep, models, agent="connect")
    start = time.time()
    reply = llm.chat([{"role": "user", "content": "Reply with the single word OK."}], alias="fast", max_tokens=1500)
    print(f"round trip ok in {time.time() - start:.1f}s: {reply[:40]!r}")
    return 0


_SSH_TARGET_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._@-]*$")


def tunnel_command(target: str, port: int, identity: str | None = None) -> list[str]:
    """Build the ssh argv for the localhost-mode tunnel. Validates input so a target can never become an ssh option."""
    if not _SSH_TARGET_RE.match(target):
        raise ModeError(f"invalid ssh target: {target!r} (use user@host or an ssh config alias)")
    if not 1 <= port <= 65535:
        raise ModeError("port must be 1-65535")
    cmd = ["ssh", "-N", "-L", f"127.0.0.1:{port}:127.0.0.1:{port}",
           "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3"]
    if identity:
        cmd += ["-i", identity]
    return cmd + ["--", target]


def cmd_tunnel(args, manifests) -> int:
    cmd = tunnel_command(args.target, args.port, args.identity)
    print("running: " + " ".join(cmd))
    print(f"then use:  nsa connect --url http://127.0.0.1:{args.port}/v1   (Ctrl+C stops the tunnel)")
    if args.dry_run:
        return 0
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        raise ModeError("ssh is not installed") from None


def cmd_route(args, manifests) -> int:
    task = _read_task(args)
    llm = _routing_llm(load_endpoints(), load_yaml("models.yaml"), Audit())
    d = route(task, manifests, llm)
    print(f"agent: {d.agent}  confidence: {d.confidence:.2f}  method: {d.method}")
    print(f"reason: {d.reason}")
    for name, s in d.candidates:
        print(f"  {name:<20} {s:5.1f}")
    return 0


def cmd_run(args, manifests) -> int:
    task = _read_task(args)
    if not task:
        _err("empty task")
        return 2
    endpoints, models, audit = load_endpoints(), load_yaml("models.yaml"), Audit()

    if args.agent:
        if args.agent not in manifests:
            _err(f"unknown agent '{args.agent}'. Installed: {', '.join(manifests)}")
            return 2
        name = args.agent
    else:
        decision = route(task, manifests, _routing_llm(endpoints, models, audit))
        name = decision.agent
        if decision.needs_confirmation and sys.stdin.isatty() and not args.dry_run:
            answer = input(f"Route to '{name}' ({decision.reason})? [Y/n/agent-name] ").strip()
            if answer in manifests:
                name = answer
            elif answer.lower() in ("n", "no"):
                return 1
        _err(f"[route] {name} via {decision.method} ({decision.reason})")

    manifest = manifests[name]
    mode, why = resolve_mode(args.mode, manifest.sensitivity, endpoints,
                             allow_sensitive_cloud=args.allow_sensitive_cloud)
    if args.dry_run:
        print(f"agent={name} mode={mode} ({why}) model={models['aliases'][manifest.model][mode]}")
        return 0

    llm = LLMClient(endpoints[mode], models, redact_level=os.environ.get("NSA_REDACT", "standard"),
                    audit=audit, agent=name)
    tools = ToolRunner(manifest.tools, _make_approver(args.yes), audit, name)
    agent = agent_class(manifest)(manifest, llm, tools, audit)
    _err(f"[run] agent={name} mode={mode} model={llm.model_for(manifest.model)}")
    audit.log("run", agent=name, mode=mode, reason=why)

    result = agent.run(task, {"files": args.file or [], "save": args.save})
    for w in result.warnings:
        _err(f"[warn] {w}")
    output = json.dumps({"agent": result.agent, "data": result.data, "warnings": result.warnings}, indent=2) \
        if args.json else result.markdown
    if args.out:
        Path(args.out).write_text(output + "\n", encoding="utf-8")
        _err(f"[saved] {args.out}")
    else:
        print(output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nsa", description="Neural Security Agent: local-first agent CLI")
    p.add_argument("--version", action="version", version=f"nsa {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list installed agents")
    d = sub.add_parser("doctor", help="check endpoints, model availability and GPU offload")
    d.add_argument("--warm", action="store_true", help="load the main local model first so GPU offload can be inspected")

    c = sub.add_parser("connect", help="point nsa at a cloud gateway and test the connection")
    c.add_argument("--url", required=True, help="gateway URL, e.g. http://100.x.y.z:4000/v1")
    c.add_argument("--key-file", help="file holding the gateway API key (otherwise you are prompted; never pass keys as arguments)")
    c.add_argument("--no-test", action="store_true", help="skip the test generation")

    t = sub.add_parser("tunnel", help="open an SSH tunnel to a gateway bound to localhost on the server")
    t.add_argument("target", help="user@host or an ssh config alias")
    t.add_argument("--port", type=int, default=4000)
    t.add_argument("-i", "--identity", help="ssh private key file")
    t.add_argument("--dry-run", action="store_true", help="print the ssh command only")

    r = sub.add_parser("route", help="show which agent a task would go to")
    r.add_argument("task", nargs="+")

    run = sub.add_parser("run", help="run a task (agent chosen automatically unless --agent)")
    run.add_argument("task", nargs="+", help="task text, or - to read stdin")
    run.add_argument("-a", "--agent", help="force a specific agent")
    run.add_argument("-m", "--mode", choices=MODES, default="auto", help="local | cloud | auto (default)")
    run.add_argument("-f", "--file", action="append", help="attach a file/dir (repeatable)")
    run.add_argument("--yes", action="store_true", help="auto-approve network tools (never write tools)")
    run.add_argument("--save", action="store_true", help="let the agent write artifacts to ./nsa_out (asks first)")
    run.add_argument("--json", action="store_true", help="print structured output")
    run.add_argument("-o", "--out", help="write the result to this file")
    run.add_argument("--dry-run", action="store_true", help="show agent and mode, do not call a model")
    run.add_argument("--allow-sensitive-cloud", action="store_true",
                     help="let high-sensitivity agents use the cloud (prompts still redacted)")
    return p


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    try:
        manifests = discover()
        return {"list": cmd_list, "doctor": cmd_doctor, "connect": cmd_connect, "tunnel": cmd_tunnel,
                 "route": cmd_route, "run": cmd_run}[args.cmd](args, manifests)
    except (ModeError, LLMError, AgentError, RegistryError, ToolError, ToolDenied) as exc:
        _err(f"error: {exc}")
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

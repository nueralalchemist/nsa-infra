"""Built-in tools. Each one is deliberately narrow: fixed argv, size caps, path and network guards."""
from __future__ import annotations

import html
import ipaddress
import os
import re
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from nsa.core.tools import ToolError, tool

MAX_FILE_BYTES = 1_000_000
MAX_FETCH_BYTES = 500_000
MAX_SCAN_OUTPUT = 2_000_000


# ---------- path guard ----------

def allowed_roots() -> list[Path]:
    roots = [Path.cwd().resolve()]
    for extra in filter(None, os.environ.get("NSA_ALLOWED_PATHS", "").split(":")):
        roots.append(Path(extra).expanduser().resolve())
    return roots


def safe_path(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not any(p == r or r in p.parents for r in allowed_roots()):
        raise ToolError(f"path outside allowed roots: {path} (run from that directory or set NSA_ALLOWED_PATHS)")
    return p


# ---------- filesystem ----------

@tool("read_file")
def read_file(path: str) -> str:
    """Read a text file (<=1MB). Refuses binary files."""
    p = safe_path(path)
    if not p.is_file():
        raise ToolError(f"not a file: {path}")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ToolError(f"file too large (>{MAX_FILE_BYTES} bytes): {path}")
    data = p.read_bytes()
    if b"\x00" in data[:8192]:
        raise ToolError(f"refusing binary file: {path} (provide a text report instead)")
    return data.decode("utf-8", "replace")


@tool("list_dir")
def list_dir(path: str, recursive: bool = False) -> list[str]:
    """List files under a directory (depth<=3, 500 entries max)."""
    root = safe_path(path)
    if not root.is_dir():
        raise ToolError(f"not a directory: {path}")
    out: list[str] = []
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - base_depth
        dirnames[:] = [d for d in dirnames if not d.startswith(".")] if recursive and depth < 3 else []
        for name in sorted(filenames):
            out.append(str(Path(dirpath, name).relative_to(root)))
            if len(out) >= 500:
                return out
        if not recursive:
            break
    return out


@tool("write_file", risk="write")
def write_file(path: str, content: str) -> str:
    """Write a file under ./nsa_out (or $NSA_OUT). Relative paths only."""
    out_root = Path(os.environ.get("NSA_OUT") or "nsa_out").resolve()
    rel = Path(path)
    if rel.is_absolute() or ".." in rel.parts:
        raise ToolError("write_file takes a relative path without '..'")
    if len(content) > MAX_FILE_BYTES:
        raise ToolError("content too large")
    target = (out_root / rel).resolve()
    if out_root not in target.parents:
        raise ToolError("path escapes the output directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return str(target)


# ---------- network ----------

def _check_public_host(host: str) -> None:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ToolError(f"cannot resolve host: {host}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ToolError(f"blocked non-public address for {host}: {ip}")


def _html_to_text(raw: str) -> str:
    raw = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", raw)
    raw = re.sub(r"(?s)<[^>]+>", " ", raw)
    return re.sub(r"\s+", " ", html.unescape(raw)).strip()


@tool("fetch_url", risk="network")
def fetch_url(url: str) -> dict:
    """GET a public http(s) page as text. Blocks private/loopback targets and caps size."""
    current = url
    with httpx.Client(timeout=15.0, follow_redirects=False, headers={"User-Agent": "nsa/0.1"}) as client:
        for _ in range(4):
            parsed = urlparse(current)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ToolError("only http(s) URLs are allowed")
            # NOTE: resolve-then-fetch leaves a small DNS-rebinding window; acceptable for a read-only fetcher.
            _check_public_host(parsed.hostname)
            with client.stream("GET", current) as resp:
                if resp.is_redirect:
                    current = urljoin(current, resp.headers.get("location", ""))
                    continue
                ctype = resp.headers.get("content-type", "")
                if not any(t in ctype for t in ("text/", "json", "xml")):
                    raise ToolError(f"unsupported content type: {ctype or 'unknown'}")
                body = b""
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > MAX_FETCH_BYTES:
                        break
                text = body[:MAX_FETCH_BYTES].decode(resp.encoding or "utf-8", "replace")
                if "html" in ctype:
                    text = _html_to_text(text)
                return {"url": current, "status": resp.status_code, "text": text, "truncated": len(body) > MAX_FETCH_BYTES}
    raise ToolError("too many redirects")


# ---------- scanners (local binaries, fixed argv) ----------

_SCANNERS = {
    "checkov": lambda p: ["checkov", "-f" if p.is_file() else "-d", str(p), "-o", "json", "--quiet", "--compact"],
    "tfsec": lambda p: ["tfsec", str(p), "--format", "json", "--no-colour"],
    "trivy": lambda p: ["trivy", "config", "--format", "json", "--quiet", str(p)],
}


def available_scanners() -> list[str]:
    return [name for name in _SCANNERS if shutil.which(name)]


@tool("run_scanner")
def run_scanner(scanner: str, path: str) -> dict:
    """Run an allowlisted IaC scanner (checkov, tfsec, trivy) against a path."""
    if scanner not in _SCANNERS:
        raise ToolError(f"scanner not allowed: {scanner}")
    if not shutil.which(scanner):
        raise ToolError(f"scanner not installed: {scanner}")
    p = safe_path(path)
    if not p.exists():
        raise ToolError(f"path does not exist: {path}")
    try:
        proc = subprocess.run(_SCANNERS[scanner](p), capture_output=True, text=True, timeout=180, shell=False)
    except subprocess.TimeoutExpired as exc:
        raise ToolError(f"{scanner} timed out") from exc
    return {
        "scanner": scanner,
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:MAX_SCAN_OUTPUT],
        "stderr_tail": proc.stderr[-500:],
    }

"""Config loading: YAML files with ${VAR:-default} expansion and a tiny .env loader."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(os.environ.get("NSA_ROOT") or Path(__file__).resolve().parents[2])
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def load_dotenv(path: Path | None = None) -> None:
    """Load KEY=VALUE lines into os.environ without overriding existing variables."""
    path = Path(path) if path else ROOT / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def set_env_values(values: dict[str, str], path: Path | None = None) -> Path:
    """Idempotently set KEY=VALUE lines in the .env file (created from .env.example, mode 0600, atomic replace)."""
    path = Path(path) if path else ROOT / ".env"
    for k, v in values.items():
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", k) or "\n" in v or "\r" in v:
            raise ValueError(f"refusing to write unsafe env entry: {k}")
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
    else:
        example = ROOT / ".env.example"
        lines = example.read_text(encoding="utf-8").splitlines() if example.is_file() else []
    remaining = dict(values)
    out = []
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if "=" in line and not line.lstrip().startswith("#") and key in remaining:
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in remaining.items()]
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out) + "\n")
    os.replace(tmp, path)
    return path


def expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1)) or m.group(2) or "", value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


def config_dir() -> Path:
    return Path(os.environ.get("NSA_CONFIG_DIR") or ROOT / "config")


def load_yaml(name: str) -> dict:
    path = config_dir() / name
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return expand_env(data)


def agents_dir() -> Path:
    return Path(os.environ.get("NSA_AGENTS_DIR") or ROOT / "agents")


def nsa_home() -> Path:
    return Path(os.environ.get("NSA_HOME") or Path.home() / ".nsa")

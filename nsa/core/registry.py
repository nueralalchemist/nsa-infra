"""Agent discovery: every folder under agents/ with an agent.yaml is an agent."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

from nsa.core.agent import Agent, Manifest
from nsa.core.config import agents_dir

SENSITIVITIES = ("low", "medium", "high")


class RegistryError(RuntimeError):
    pass


def load_manifest(folder: Path) -> Manifest:
    raw = yaml.safe_load((folder / "agent.yaml").read_text(encoding="utf-8")) or {}
    name = raw.get("name")
    if name != folder.name:
        raise RegistryError(f"{folder}: agent.yaml name '{name}' must match folder name '{folder.name}'")
    if not raw.get("description"):
        raise RegistryError(f"{name}: description is required")
    sensitivity = raw.get("sensitivity", "medium")
    if sensitivity not in SENSITIVITIES:
        raise RegistryError(f"{name}: sensitivity must be one of {SENSITIVITIES}")
    return Manifest(
        name=name,
        description=raw["description"].strip(),
        keywords=[str(k) for k in raw.get("keywords", [])],
        model=raw.get("model", "main"),
        sensitivity=sensitivity,
        tools=list(raw.get("tools", [])),
        entrypoint=raw.get("entrypoint"),
        system_prompt=(raw.get("system_prompt") or "").strip(),
        fallback=bool(raw.get("fallback", False)),
        path=folder,
    )


def discover(directory: Path | None = None) -> dict[str, Manifest]:
    directory = Path(directory) if directory else agents_dir()
    found: dict[str, Manifest] = {}
    if not directory.is_dir():
        return found
    for folder in sorted(p for p in directory.iterdir() if (p / "agent.yaml").is_file()):
        manifest = load_manifest(folder)
        found[manifest.name] = manifest
    return found


def agent_class(manifest: Manifest) -> type[Agent]:
    """Import the agent's entrypoint. Only files inside the agent's own folder are allowed."""
    if not manifest.entrypoint:
        return Agent
    filename, _, classname = manifest.entrypoint.partition(":")
    path = (manifest.path / filename).resolve()
    if manifest.path.resolve() not in path.parents or not path.is_file():
        raise RegistryError(f"{manifest.name}: entrypoint must be a file inside the agent folder")
    spec = importlib.util.spec_from_file_location(f"nsa_agent_{manifest.name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # executes code from the agents/ folder: only install agents you trust
    cls = getattr(module, classname, None)
    if not (isinstance(cls, type) and issubclass(cls, Agent)):
        raise RegistryError(f"{manifest.name}: {manifest.entrypoint} is not an Agent subclass")
    return cls

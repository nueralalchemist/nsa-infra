"""Mode resolution: local | cloud | auto, with a sensitivity gate for the cloud."""
from __future__ import annotations

from typing import Callable

from nsa.core.config import load_yaml
from nsa.core.llm import Endpoint, probe

MODES = ("local", "cloud", "auto")


class ModeError(RuntimeError):
    pass


def load_endpoints() -> dict[str, Endpoint]:
    raw = load_yaml("endpoints.yaml")
    return {
        mode: Endpoint(mode, (raw.get(mode) or {}).get("base_url", ""), (raw.get(mode) or {}).get("api_key", ""))
        for mode in ("local", "cloud")
    }


def resolve_mode(
    requested: str,
    sensitivity: str,
    endpoints: dict[str, Endpoint],
    *,
    allow_sensitive_cloud: bool = False,
    prober: Callable[[Endpoint], bool] = probe,
) -> tuple[str, str]:
    """Return (mode, reason). Raises ModeError when no safe endpoint is available."""
    if requested not in MODES:
        raise ModeError(f"unknown mode '{requested}' (use local, cloud or auto)")
    cloud_blocked = sensitivity == "high" and not allow_sensitive_cloud
    cloud = endpoints["cloud"]

    if requested == "local":
        return "local", "requested"
    if requested == "cloud":
        if cloud_blocked:
            raise ModeError(
                "this agent handles high-sensitivity data and is local-only. "
                "Use --allow-sensitive-cloud to override (prompts are still redacted)."
            )
        if not cloud.configured:
            raise ModeError("cloud endpoint not configured (set NSA_CLOUD_URL)")
        return "cloud", "requested"

    # auto
    if prober(endpoints["local"]):
        return "local", "local endpoint reachable"
    if cloud_blocked:
        raise ModeError("local endpoint unreachable and this agent is local-only (high sensitivity)")
    if not cloud.configured:
        raise ModeError("local endpoint unreachable and no cloud endpoint configured")
    return "cloud", "local endpoint unreachable, fell back to cloud"

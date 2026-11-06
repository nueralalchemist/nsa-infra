"""Tool registry with risk tiers and per-agent allowlists.

Risk tiers:  read     runs automatically
             network  needs approval (--yes grants it for the run)
             write    always needs an interactive approval
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from nsa.core.audit import Audit


class ToolError(RuntimeError):
    """The tool ran but could not do what was asked (bad input, blocked target...)."""


class ToolDenied(PermissionError):
    """The tool is not allowed for this agent, or the user declined it."""


@dataclass(frozen=True)
class Tool:
    name: str
    risk: str
    fn: Callable
    doc: str = ""


REGISTRY: dict[str, Tool] = {}


def tool(name: str, risk: str = "read"):
    assert risk in ("read", "network", "write")

    def deco(fn: Callable) -> Callable:
        REGISTRY[name] = Tool(name, risk, fn, (fn.__doc__ or "").strip())
        return fn

    return deco


Approver = Callable[[Tool, dict], bool]


class ToolRunner:
    def __init__(self, allowed: list[str], approver: Approver | None = None, audit: Audit | None = None, agent: str = ""):
        from nsa.tools import builtin  # noqa: F401  (registers builtin tools)

        self.allowed = set(allowed)
        self.approver = approver
        self.audit = audit
        self.agent = agent

    def call(self, name: str, **kwargs):
        if name not in self.allowed or name not in REGISTRY:
            self._log("tool_blocked", name, kwargs)
            raise ToolDenied(f"tool '{name}' is not available to agent '{self.agent}'")
        t = REGISTRY[name]
        if t.risk != "read" and not (self.approver and self.approver(t, kwargs)):
            self._log("tool_declined", name, kwargs)
            raise ToolDenied(f"tool '{name}' ({t.risk}) was not approved")
        self._log("tool_call", name, kwargs)
        return t.fn(**kwargs)

    def _log(self, event: str, name: str, kwargs: dict) -> None:
        if not self.audit:
            return
        safe = {k: (f"<{len(v)} chars>" if k == "content" else str(v)[:120]) for k, v in kwargs.items()}
        self.audit.log(event, agent=self.agent, tool=name, args=safe)

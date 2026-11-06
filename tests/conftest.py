import pytest

from nsa.core.agent import Manifest
from nsa.core.registry import discover
from nsa.core.tools import ToolRunner


class FakeLLM:
    """Scripted stand-in for LLMClient: returns queued replies in order."""

    mode = "local"

    def __init__(self, *replies: str):
        self.replies = list(replies)
        self.calls: list[list[dict]] = []

    def chat(self, messages, alias="main", **kw):
        self.calls.append(messages)
        if not self.replies:
            raise AssertionError("FakeLLM ran out of replies")
        return self.replies.pop(0)


@pytest.fixture
def manifests():
    return discover()


@pytest.fixture
def make_agent(manifests):
    from nsa.core.registry import agent_class

    def _make(name: str, llm: FakeLLM, approve=True):
        m: Manifest = manifests[name]
        tools = ToolRunner(m.tools, approver=lambda t, a: approve, agent=name)
        return agent_class(m)(m, llm, tools)

    return _make

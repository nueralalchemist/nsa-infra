from conftest import FakeLLM

from nsa.router import route


def test_keyword_routing_for_each_specialist(manifests):
    cases = {
        "write a sigma detection rule for encoded powershell": "detection_as_code",
        "review the terraform in ./infra for misconfiguration": "iac_review",
        "triage this suspicious login alert from the SIEM": "soc_triage",
        "analyse this capa output from a ransomware dropper": "malware_triage",
        "research the latest arxiv paper on agent security": "research",
    }
    for task, expected in cases.items():
        d = route(task, manifests)
        assert d.agent == expected, (task, d)
        assert d.method == "keyword"


def test_fallback_agent_does_not_steal_specialist_tasks(manifests):
    # "write" is an assistant keyword, but a sigma request must still route by keyword to the specialist.
    d = route("write a sigma rule for lsass dumping", manifests)
    assert (d.agent, d.method) == ("detection_as_code", "keyword")
    assert "assistant" not in dict(d.candidates)


def test_no_match_falls_back_to_assistant(manifests):
    d = route("what is a good name for a puppy", manifests)
    assert d.agent == "assistant" and d.method == "fallback"


def test_llm_breaks_ties_and_flags_low_confidence(manifests):
    d = route("zzz unknown thing", manifests, FakeLLM('{"agent": "research", "confidence": 0.9}'))
    assert (d.agent, d.method, d.needs_confirmation) == ("research", "llm", False)
    d = route("zzz unknown thing", manifests, FakeLLM('{"agent": "research", "confidence": 0.2}'))
    assert d.needs_confirmation


def test_bad_llm_output_degrades_to_fallback(manifests):
    d = route("zzz unknown thing", manifests, FakeLLM("not json at all"))
    assert d.agent == "assistant"

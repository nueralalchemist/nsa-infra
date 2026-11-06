import pytest

from nsa.tools import sigma

RULE = """
title: Encoded PowerShell
status: experimental
description: Detects encoded PowerShell command lines.
tags: [attack.execution, attack.t1059.001]
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -encodedcommand '
  filter:
    ParentImage|endswith: '\\ccmexec.exe'
  condition: selection and not filter
falsepositives: [Admin scripts]
level: high
"""


def event(**kw):
    return {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell -enc AAAA", **kw}


def test_valid_rule_passes_and_normalizes():
    rule = sigma.parse_rule(RULE)
    assert sigma.validate(rule) == []
    out = sigma.normalize(rule, today="2026-11-06")
    assert list(out)[:3] == ["title", "id", "status"] and out["date"] == "2026-11-06"
    assert sigma.validate(out) == []


def test_validation_catches_common_model_mistakes():
    rule = sigma.parse_rule(RULE)
    rule["detection"]["condition"] = "selection and missing_one"
    rule["tags"] = ["attack.T9999", "mitre.execution"]
    rule["level"] = "severe"
    errs = " | ".join(sigma.validate(rule))
    assert "missing_one" in errs and "mitre.execution" in errs and "level" in errs


def test_parse_accepts_fenced_yaml_and_rejects_garbage():
    assert sigma.parse_rule(f"Here you go:\n```yaml\n{RULE}\n```")["title"] == "Encoded PowerShell"
    with pytest.raises(sigma.SigmaError):
        sigma.parse_rule("just prose, not a rule")


def test_duplicate_yaml_keys_are_rejected_with_a_useful_hint():
    dup = RULE.replace("    CommandLine|contains:\n      - ' -enc '\n      - ' -encodedcommand '\n",
                       "    CommandLine|contains: ' -enc '\n    CommandLine|contains: ' -encodedcommand '\n")
    with pytest.raises(sigma.SigmaError, match="duplicate key 'CommandLine\\|contains'.*list"):
        sigma.parse_rule(dup)


def test_matching_semantics():
    rule = sigma.parse_rule(RULE)
    assert sigma.matches(rule, event())
    assert not sigma.matches(rule, event(CommandLine="powershell -File x.ps1"))
    assert not sigma.matches(rule, event(ParentImage="C:\\Windows\\CCM\\CcmExec.exe"))  # filter, case-insensitive
    assert sigma.matches(rule, {k.lower(): v for k, v in event().items()})  # field names are case-insensitive


def test_quantifiers_and_all_modifier():
    rule = {"detection": {"sel_a": {"a": "1"}, "sel_b": {"b": "2"}, "kw": {"c|contains|all": ["x", "y"]},
                          "condition": "1 of sel_* and kw"}}
    assert sigma.matches(rule, {"a": "1", "c": "xy"})
    assert not sigma.matches(rule, {"a": "9", "b": "9", "c": "xy"})
    assert not sigma.matches(rule, {"a": "1", "c": "x"})
    rule["detection"]["condition"] = "all of sel_*"
    assert not sigma.matches(rule, {"a": "1"})


def test_unsupported_features_raise_instead_of_guessing():
    rule = {"detection": {"s": {"a|base64": "x"}, "condition": "s"}}
    with pytest.raises(sigma.SigmaUnsupported):
        sigma.matches(rule, {"a": "x"})
    rule = {"detection": {"s": {"a": "x"}, "condition": "s | count() > 5"}}
    with pytest.raises(sigma.SigmaUnsupported):
        sigma.matches(rule, {"a": "x"})

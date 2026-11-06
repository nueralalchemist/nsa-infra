from __future__ import annotations

import json
import re
import time

from nsa.core.agent import Agent, AgentError, Result, paths_from
from nsa.tools import sigma

SYSTEM = """You are a detection engineer writing Sigma rules (https://sigmahq.io).
Output ONLY one YAML document in a ```yaml fence. Required keys:
title, status (experimental), description, tags (e.g. attack.execution, attack.t1059.001),
logsource (product/category/service), detection (named selections + condition),
falsepositives (list), level (informational|low|medium|high|critical).
Rules: use real Sigma field names for the log source (e.g. Image, CommandLine, ParentImage for process_creation);
prefer |contains / |endswith modifiers over regex; every name in condition must be defined in detection;
do not invent ATT&CK IDs: if unsure of the sub-technique use the parent technique.
The condition is a boolean expression over the NAMES of the blocks you defined under detection
(e.g. "selection", "selection and not filter", "1 of selection_*"), never over field names.
A field may appear only once per block: put several values in a list.

Example of a correct rule:
```yaml
title: Suspicious Certutil Download
status: experimental
description: Detects certutil used to download a file from a URL.
tags:
  - attack.command_and_control
  - attack.t1105
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - '-urlcache'
      - 'http'
  condition: selection
falsepositives:
  - Administrators fetching certificates
level: medium
```"""

MAX_ATTEMPTS = 3

SAMPLES = (
    "You test Sigma rules. Given a rule, produce realistic log events as flat JSON objects using EXACTLY the field "
    "names that appear in the rule's detection block. "
    'JSON keys: "malicious_events" and "benign_events", each a JSON ARRAY of 2 event objects '
    "(malicious: SHOULD be detected by this rule; benign: normal activity that should NOT match). "
    "Each event is an object whose field values are strings. Keep values short; for any encoded or base64 "
    'payload just write "AAAA".'
)


def _as_events(value) -> list[dict] | None:
    """Small models often return a list as a JSON-encoded string, or a single object. Accept both."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return None
    if isinstance(value, dict):
        value = [value]
    return value if isinstance(value, list) and all(isinstance(e, dict) for e in value) else None


class DetectionAsCodeAgent(Agent):
    def run(self, task: str, opts: dict | None = None) -> Result:
        opts = opts or {}
        feedback, rule, attempts, self_test, warnings = "", None, 0, None, []
        for attempts in range(1, MAX_ATTEMPTS + 1):
            prompt = task if not feedback else f"{task}\n\nYour previous rule failed:\n{feedback}\nReturn the complete fixed rule."
            try:
                candidate = sigma.parse_rule(self.ask(SYSTEM, prompt))
                errors = sigma.validate(candidate)
            except sigma.SigmaError as exc:
                candidate, errors = None, [str(exc)]
            if errors:
                feedback = "\n".join(f"- {e}" for e in errors)
                continue
            # Valid syntax is not enough: the rule must catch its own attack and ignore normal activity.
            self_test = self._self_test(candidate)
            rule = candidate
            if self_test["status"] != "failed":
                break
            feedback = "- " + self_test["detail"]
        if rule is None:
            raise AgentError(f"could not produce a valid Sigma rule after {MAX_ATTEMPTS} attempts:\n{feedback}")
        if self_test and self_test["status"] == "failed":
            warnings.append("rule is valid but failed its own self-test: " + self_test["detail"])
        elif self_test and self_test["status"] == "skipped":
            warnings.append("self-test skipped: " + self_test["detail"])

        rule = sigma.normalize(rule, today=time.strftime("%Y-%m-%d"))
        text = sigma.dump(rule)
        if attempts > 1:
            warnings.append(f"rule needed {attempts} attempts")
        md = ["# Sigma rule\n", f"```yaml\n{text}```\n"]
        data: dict = {"rule": rule, "attempts": attempts, "self_test": self_test}
        if self_test and self_test["status"] == "passed":
            md.append(f"**Self-test:** {self_test['detail']}\n")

        # Optional: test against sample events (JSON lines or a JSON array) passed with --file.
        for path in paths_from(task, opts):
            try:
                events = self._events(self.tools.call("read_file", path=path))
            except (ValueError, OSError) as exc:
                warnings.append(f"{path}: {exc}")
                continue
            try:
                hits = [i for i, e in enumerate(events) if sigma.matches(rule, e)]
            except sigma.SigmaError as exc:
                warnings.append(f"{path}: cannot evaluate rule locally ({exc})")
                continue
            md.append(f"**Test against `{path}`:** {len(hits)} of {len(events)} events matched" +
                      (f" (indexes {hits[:20]})" if hits else ""))
            data.setdefault("tests", []).append({"file": path, "events": len(events), "matches": len(hits)})

        if opts.get("save"):
            slug = re.sub(r"[^a-z0-9]+", "_", rule["title"].lower()).strip("_")[:60] or "rule"
            data["saved_to"] = self.tools.call("write_file", path=f"sigma/{slug}.yml", content=text)
            md.append(f"\nSaved to `{data['saved_to']}`")
        return Result(self.manifest.name, "\n".join(md), data, warnings)

    def _self_test(self, rule: dict) -> dict:
        """Ask the model for sample events, then check the rule against them with the local matcher."""
        try:
            samples = self.ask_json(SAMPLES, sigma.dump(rule), ["malicious_events", "benign_events"], retries=1)
            bad, good = _as_events(samples["malicious_events"]), _as_events(samples["benign_events"])
            if not bad or good is None:
                return {"status": "skipped", "detail": "model returned unusable sample events"}
            missed = [e for e in bad if not sigma.matches(rule, e)]
            false_hits = [e for e in good if sigma.matches(rule, e)]
        except sigma.SigmaUnsupported as exc:
            return {"status": "skipped", "detail": f"rule uses a feature the local matcher does not support ({exc})"}
        except (AgentError, sigma.SigmaError) as exc:
            return {"status": "skipped", "detail": str(exc)}
        if missed:
            return {"status": "failed", "detail": f"the rule did NOT match this event it should detect: {json.dumps(missed[0])}. "
                    "Check that the condition combines your selections correctly and that every field value matches."}
        if false_hits:
            return {"status": "failed", "detail": f"the rule wrongly matched this normal event: {json.dumps(false_hits[0])}. Make it more specific."}
        return {"status": "passed", "detail": f"{len(bad)}/{len(bad)} malicious events matched, 0/{len(good)} benign events matched"}

    @staticmethod
    def _events(raw: str) -> list[dict]:
        raw = raw.strip()
        if raw.startswith("["):
            events = json.loads(raw)
        else:
            events = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if not all(isinstance(e, dict) for e in events):
            raise ValueError("expected JSON objects")
        return events

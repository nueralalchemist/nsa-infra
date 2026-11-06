"""Sigma helpers: parse, validate and a small matcher for testing rules against JSON events.

The matcher covers the common subset (field equality, contains/startswith/endswith/re/all
modifiers, wildcards, and/or/not/parentheses, '1 of'/'all of' quantifiers). Anything else
(aggregations, base64, cidr...) raises SigmaUnsupported rather than guessing.
"""
from __future__ import annotations

import fnmatch
import json
import re
import uuid

import yaml

LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
TAG_RE = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z][a-z_]+)$")
KEY_ORDER = ["title", "id", "status", "description", "references", "author", "date", "tags",
             "logsource", "detection", "falsepositives", "level"]
_SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "cased", "i", "m", "s"}
_MISSING = object()


class SigmaError(ValueError):
    pass


class SigmaUnsupported(SigmaError):
    pass


# ---------- parse / validate ----------

def extract_yaml(text: str) -> str:
    m = re.search(r"```(?:ya?ml)?\s*\n(.*?)```", text, re.S)
    return (m.group(1) if m else text).strip()


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of silently keeping the last one."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise SigmaError(
                    f"duplicate key '{key}': a YAML key may appear only once. To match several values for one field, "
                    f"give a list under a single key (e.g. {key}: [value1, value2])"
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def parse_rule(text: str) -> dict:
    try:
        data = yaml.load(extract_yaml(text), Loader=_StrictLoader)  # noqa: S506 (SafeLoader subclass)
    except yaml.YAMLError as exc:
        raise SigmaError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise SigmaError("rule must be a YAML mapping")
    return data


def _is_uuid(value) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


def _condition_names(cond: str) -> list[str]:
    reserved = {"and", "or", "not", "of", "them", "all", "1"}
    return [t for t in re.findall(r"[^\s()]+", cond) if t.lower() not in reserved]


def validate(rule: dict) -> list[str]:
    errs: list[str] = []
    if not isinstance(rule.get("title"), str) or not rule["title"].strip():
        errs.append("title is required (string)")
    if not isinstance(rule.get("description"), str) or not rule["description"].strip():
        errs.append("description is required (string)")
    if rule.get("level") not in LEVELS:
        errs.append(f"level must be one of {sorted(LEVELS)}")
    if rule.get("status") not in STATUSES:
        errs.append(f"status must be one of {sorted(STATUSES)}")
    if "id" in rule and not _is_uuid(rule["id"]):
        errs.append("id must be a UUID")
    ls = rule.get("logsource")
    if not isinstance(ls, dict) or not any(ls.get(k) for k in ("product", "category", "service")):
        errs.append("logsource needs at least one of product, category, service")
    fp = rule.get("falsepositives")
    if not isinstance(fp, list) or not fp:
        errs.append("falsepositives must be a non-empty list")
    tags = rule.get("tags")
    if tags is not None:
        if not isinstance(tags, list):
            errs.append("tags must be a list")
        else:
            errs += [f"invalid tag '{t}' (expected attack.t1059.001 or attack.execution)" for t in tags if not TAG_RE.match(str(t))]
    det = rule.get("detection")
    if not isinstance(det, dict) or not isinstance(det.get("condition"), str):
        errs.append("detection.condition is required (string)")
    else:
        names = {k for k in det if k not in ("condition", "timeframe")}
        if not names:
            errs.append("detection needs at least one selection")
        for ref in _condition_names(det["condition"]):
            if "*" in ref:
                if not fnmatch.filter(names, ref):
                    errs.append(f"condition pattern '{ref}' matches no selection")
            elif ref not in names and ref != "|":
                errs.append(f"condition references undefined selection '{ref}'")
    return errs


def normalize(rule: dict, *, author: str = "NSA", today: str = "") -> dict:
    """Fill id/date/author defaults and order keys canonically."""
    rule = dict(rule)
    if not _is_uuid(rule.get("id")):
        rule["id"] = str(uuid.uuid4())
    if today and not rule.get("date"):
        rule["date"] = today
    rule.setdefault("author", author)
    ordered = {k: rule[k] for k in KEY_ORDER if k in rule}
    ordered.update({k: v for k, v in rule.items() if k not in ordered})
    return ordered


def dump(rule: dict) -> str:
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, default_flow_style=False)


# ---------- matcher ----------

def _lookup(event, field: str):
    if not isinstance(event, dict):
        return _MISSING
    for k, v in event.items():
        if k == field or str(k).lower() == field.lower():
            return v
    if "." in field:
        head, rest = field.split(".", 1)
        nested = _lookup(event, head)
        if nested is not _MISSING:
            return _lookup(nested, rest)
    return _MISSING


def _wildcard_regex(pattern: str) -> re.Pattern:
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.I | re.S)


def _match_value(actual, expected, mods: list[str]) -> bool:
    if expected is None:
        return actual is _MISSING or actual is None
    if actual is _MISSING or actual is None:
        return False
    a, e = str(actual), str(expected)
    if "re" in mods:
        return re.search(e, a, 0 if "cased" in mods else re.I) is not None
    if "contains" in mods:
        e = f"*{e}*"
    elif "startswith" in mods:
        e = f"{e}*"
    elif "endswith" in mods:
        e = f"*{e}"
    return _wildcard_regex(e).match(a) is not None


def _eval_field(key: str, expected, event: dict) -> bool:
    field, *mods = key.split("|")
    mods = [m.lower() for m in mods]
    bad = [m for m in mods if m not in _SUPPORTED_MODS]
    if bad:
        raise SigmaUnsupported(f"unsupported modifier(s): {bad}")
    actual = _lookup(event, field)
    values = expected if isinstance(expected, list) else [expected]
    results = [_match_value(actual, v, mods) for v in values]
    return all(results) if "all" in mods else any(results)


def _eval_selection(sel, event: dict) -> bool:
    if isinstance(sel, dict):
        return all(_eval_field(k, v, event) for k, v in sel.items())
    if isinstance(sel, list):
        if sel and all(isinstance(x, dict) for x in sel):
            return any(_eval_selection(x, event) for x in sel)
        blob = json.dumps(event, default=str).lower()
        return any(str(x).lower() in blob for x in sel)
    raise SigmaError("selection must be a mapping or a list")


class _Condition:
    def __init__(self, cond: str, detection: dict, event: dict):
        if "|" in cond:
            raise SigmaUnsupported("aggregation conditions are not supported")
        self.tokens = re.findall(r"\(|\)|[^\s()]+", cond)
        self.pos = 0
        self.det, self.event = detection, event
        self.cache: dict[str, bool] = {}

    def _peek(self):
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _sel(self, name: str) -> bool:
        if name not in self.det:
            raise SigmaError(f"undefined selection '{name}'")
        if name not in self.cache:
            self.cache[name] = _eval_selection(self.det[name], self.event)
        return self.cache[name]

    def parse(self) -> bool:
        result = self._or()
        if self.pos != len(self.tokens):
            raise SigmaError("trailing tokens in condition")
        return result

    def _or(self) -> bool:
        left = self._and()
        while self._peek() == "or":
            self._next()
            right = self._and()
            left = left or right
        return left

    def _and(self) -> bool:
        left = self._not()
        while self._peek() == "and":
            self._next()
            right = self._not()
            left = left and right
        return left

    def _not(self) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self) -> bool:
        tok = self._peek()
        if tok is None:
            raise SigmaError("unexpected end of condition")
        if tok == "(":
            self._next()
            value = self._or()
            if self._peek() != ")":
                raise SigmaError("missing ')'")
            self._next()
            return value
        if tok in ("1", "all") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            self._next()
            self._next()
            target = self._next()
            names = [k for k in self.det if k not in ("condition", "timeframe")
                     and (target.lower() == "them" or fnmatch.fnmatchcase(k, target))]
            if not names:
                return False
            vals = [self._sel(n) for n in names]
            return all(vals) if tok == "all" else any(vals)
        return self._sel(self._next())


def matches(rule: dict, event: dict) -> bool:
    det = rule.get("detection") or {}
    return _Condition(det.get("condition", ""), det, event).parse()

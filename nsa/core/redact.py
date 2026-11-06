"""Reversible redaction for prompts that leave the machine (cloud mode).

Sensitive values are swapped for placeholders like [[IP_1]] before sending, and the
placeholders in the model's reply are swapped back, so analysis still reads naturally.
"""
from __future__ import annotations

import re

_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{12,})")
_SECRET_ASSIGN = re.compile(
    r"(?i)\b((?:api[_-]?key|secret|token|passwd|password|pwd|authorization)\s*[:=]\s*)([\"']?)([^\s\"',;]{6,})"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_PLACEHOLDER = re.compile(r"\[\[[A-Z]+_\d+\]\]")


def _is_private_ip(ip: str) -> bool:
    a, b, *_ = (int(x) for x in ip.split("."))
    return a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254)


class Redactor:
    def __init__(self, level: str = "standard"):
        if level not in ("standard", "strict", "off"):
            raise ValueError(f"unknown redaction level: {level}")
        self.level = level
        self._fwd: dict[tuple[str, str], str] = {}
        self._rev: dict[str, str] = {}
        self._count: dict[str, int] = {}

    def _placeholder(self, kind: str, value: str) -> str:
        key = (kind, value)
        if key not in self._fwd:
            n = self._count[kind] = self._count.get(kind, 0) + 1
            token = f"[[{kind}_{n}]]"
            self._fwd[key] = token
            self._rev[token] = value
        return self._fwd[key]

    def redact(self, text: str) -> str:
        if self.level == "off":
            return text
        text = _PRIVATE_KEY.sub(lambda m: self._placeholder("PRIVKEY", m.group(0)), text)
        text = _AWS_KEY.sub(lambda m: self._placeholder("AWSKEY", m.group(0)), text)
        text = _JWT.sub(lambda m: self._placeholder("JWT", m.group(0)), text)
        text = _BEARER.sub(lambda m: "Bearer " + self._placeholder("TOKEN", m.group(1)), text)
        text = _SECRET_ASSIGN.sub(
            lambda m: m.group(1) + m.group(2) + self._placeholder("SECRET", m.group(3)), text
        )
        text = _EMAIL.sub(lambda m: self._placeholder("EMAIL", m.group(0)), text)

        def ip(m: re.Match) -> str:
            if self.level == "strict" or _is_private_ip(m.group(0)):
                return self._placeholder("IP", m.group(0))
            return m.group(0)

        return _IPV4.sub(ip, text)

    def restore(self, text: str) -> str:
        if not self._rev:
            return text
        return _PLACEHOLDER.sub(lambda m: self._rev.get(m.group(0), m.group(0)), text)

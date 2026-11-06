"""Append-only JSONL audit log. Records metadata and hashes, never prompt/response content."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from nsa.core.config import nsa_home


def sha256_short(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


class Audit:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else nsa_home() / "audit.jsonl"

    def log(self, event: str, **fields) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event, **fields}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError:
            pass  # auditing must never break the task

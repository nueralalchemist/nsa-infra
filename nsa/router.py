"""Task -> agent routing.

Stage 1: keyword/description scoring (free, deterministic).
Stage 2: only when stage 1 is ambiguous, ask a small model to choose among the top candidates.
Stage 3: if still unsure, flag the decision so the CLI can ask the user.
The routing model call always goes to the LOCAL endpoint: the task text is never sent to the cloud for routing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from nsa.core.agent import AgentError, Manifest, extract_json

MIN_SCORE = 3.0
DOMINANCE = 1.8
_STOP = {"the", "and", "for", "with", "that", "this", "from", "into", "your", "are", "you", "have", "will",
         "can", "any", "all", "its", "their", "them", "then", "than", "also", "such", "using", "used", "use"}


@dataclass
class RouteDecision:
    agent: str
    confidence: float
    method: str  # keyword | llm | fallback
    candidates: list[tuple[str, float]] = field(default_factory=list)
    needs_confirmation: bool = False
    reason: str = ""


def _stem(word: str) -> str:
    for suffix in ("ing", "ed", "es", "s"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            return word[: -len(suffix)]
    return word


def score(task: str, m: Manifest) -> float:
    low = task.lower()
    raw_tokens = re.findall(r"[a-z0-9._\-/]+", low)
    words = {_stem(t) for t in re.findall(r"[a-z0-9]+", low)}
    total = 0.0
    for kw in m.keywords:
        k = kw.lower().strip()
        if not k:
            continue
        if k.startswith("."):  # file extension hint
            hit, weight = any(t.endswith(k) for t in raw_tokens), 3.0
        elif re.search(r"[\s.\-/]", k):  # phrase
            hit, weight = k in low, 4.0
        else:
            hit, weight = _stem(k) in words, 3.0
        total += weight if hit else 0.0
    desc = {_stem(w) for w in re.findall(r"[a-z]+", m.description.lower()) if len(w) > 3 and w not in _STOP}
    return total + 0.5 * len(desc & words)


def route(task: str, manifests: dict[str, Manifest], llm=None, threshold: float = 0.6) -> RouteDecision:
    if not manifests:
        raise AgentError("no agents installed")
    # The generic fallback agent never competes on keywords: it is what you get when no specialist matches.
    specialists = {n: m for n, m in manifests.items() if not m.fallback} or manifests
    scored = sorted(((n, score(task, m)) for n, m in specialists.items()), key=lambda x: x[1], reverse=True)
    fallback = next((n for n, m in manifests.items() if m.fallback), scored[0][0])
    (top, top_s), second_s = scored[0], (scored[1][1] if len(scored) > 1 else 0.0)

    if top_s >= MIN_SCORE and top_s >= DOMINANCE * second_s:
        return RouteDecision(top, 0.9, "keyword", scored, reason=f"keyword score {top_s:.1f} vs {second_s:.1f}")

    if llm is not None:
        pool = [n for n, _ in scored[:3]] if top_s >= MIN_SCORE else list(manifests)
        try:
            choice = _ask_llm(task, [manifests[n] for n in pool], llm)
            name, conf = choice["agent"], float(choice.get("confidence", 0))
            if name in manifests:
                return RouteDecision(name, conf, "llm", scored, needs_confirmation=conf < threshold,
                                     reason=f"model chose {name} ({conf:.2f})")
        except Exception:  # LLM unavailable or bad output: fall through to deterministic fallback
            pass

    if top_s >= MIN_SCORE:
        return RouteDecision(top, 0.5, "keyword", scored, needs_confirmation=True,
                             reason=f"ambiguous: {top_s:.1f} vs {second_s:.1f}")
    return RouteDecision(fallback, 0.3, "fallback", scored, reason="no agent matched; using fallback")


def _ask_llm(task: str, pool: list[Manifest], llm) -> dict:
    menu = "\n".join(f"- {m.name}: {m.description}" for m in pool)
    messages = [
        {"role": "system", "content": "You route tasks to the best agent. Reply with JSON only: "
                                      '{"agent": "<name>", "confidence": <0..1>}.'},
        {"role": "user", "content": f"Agents:\n{menu}\n\nTask:\n{task[:2000]}"},
    ]
    return extract_json(llm.chat(messages, alias="fast", json_mode=True, max_tokens=100))

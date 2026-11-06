from __future__ import annotations

import re

from nsa.core.agent import Agent, AgentError, Result, untrusted
from nsa.core.tools import ToolDenied, ToolError

READER = (
    "You are a security research analyst. Summarise the document for a senior security engineer. "
    'JSON keys: "title" (string), "summary" (3-5 sentences), "key_points" (list of strings), '
    '"security_relevance" (string), "iocs_or_cves" (list of strings quoted from the text), '
    '"follow_ups" (list of strings). Use only what the document says; do not add outside facts.'
)

PLANNER = (
    "You are a security research planner. There are no source documents, so do NOT claim facts about recent events. "
    'JSON keys: "background" (short orientation from general knowledge), "questions" (list of 5-8 sharp research '
    'questions), "search_queries" (list of 5-8 queries), "sources_to_check" (list of source types or named venues).'
)


class ResearchAgent(Agent):
    def run(self, task: str, opts: dict | None = None) -> Result:
        urls = re.findall(r"https?://[^\s)>\]]+", task)[:3]
        if not urls:
            return self._plan(task)

        warnings: list[str] = []
        notes: list[tuple[str, dict]] = []
        for url in urls:
            try:
                page = self.tools.call("fetch_url", url=url)
            except (ToolError, ToolDenied) as exc:
                warnings.append(f"{url}: {exc}")
                continue
            # Reader step: untrusted web text goes in, structured summary comes out, no tools involved.
            summary = self.ask_json(READER, untrusted(url, page["text"]), ["title", "summary", "key_points"])
            if page.get("truncated"):
                warnings.append(f"{url}: page truncated, summary covers the first part only")
            notes.append((url, summary))
        if not notes:
            raise AgentError("none of the URLs could be fetched: " + "; ".join(warnings))

        parts = ["# Research digest\n"]
        for url, n in notes:
            parts.append(f"## {n.get('title') or url}\n<{url}>\n\n{n.get('summary', '')}\n")
            parts.append("**Key points**\n" + "\n".join(f"- {p}" for p in n.get("key_points", [])))
            if n.get("security_relevance"):
                parts.append(f"\n**Security relevance:** {n['security_relevance']}")
            if n.get("iocs_or_cves"):
                parts.append("\n**IOCs / CVEs:** " + ", ".join(map(str, n["iocs_or_cves"])))
            if n.get("follow_ups"):
                parts.append("\n**Follow-ups**\n" + "\n".join(f"- {f}" for f in n["follow_ups"]))
            parts.append("")
        return Result(self.manifest.name, "\n".join(parts), {"sources": [dict(url=u, **n) for u, n in notes]}, warnings)

    def _plan(self, task: str) -> Result:
        plan = self.ask_json(PLANNER, task, ["questions", "search_queries"])
        md = ["# Research plan\n", "_No sources were fetched. This is a plan from model knowledge: verify everything._\n"]
        if plan.get("background"):
            md.append(f"{plan['background']}\n")
        for title, key in (("Questions", "questions"), ("Search queries", "search_queries"),
                           ("Sources to check", "sources_to_check")):
            if plan.get(key):
                md.append(f"## {title}\n" + "\n".join(f"- {x}" for x in plan[key]) + "\n")
        return Result(self.manifest.name, "\n".join(md), plan, ["no sources fetched: model knowledge only"])

from __future__ import annotations

import json
from pathlib import Path

from nsa.core.agent import Agent, AgentError, Result, paths_from, untrusted
from nsa.core.tools import ToolError
from nsa.tools.builtin import available_scanners

IAC_SUFFIXES = {".tf", ".tfvars", ".yaml", ".yml", ".json", ".hcl"}
MAX_SNIPPET_CHARS = 9000
MAX_FINDINGS = 30

REVIEWER = (
    "You are an infrastructure security reviewer. You get scanner findings and/or IaC source as data. "
    'JSON keys: "overall_risk" (low|medium|high|critical), "summary" (2-4 sentences), '
    '"findings" (list of {"id","severity","resource","explanation","fix"}). '
    "Base every finding on the provided scanner output or code. In fix, give a concrete code change. "
    "Do not invent resource names. If there is nothing wrong, return an empty findings list."
)


def parse_findings(scanner: str, stdout: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    if scanner == "checkov":
        for item in data if isinstance(data, list) else [data]:
            for c in (item.get("results") or {}).get("failed_checks", []):
                out.append({"id": c.get("check_id"), "title": c.get("check_name"), "resource": c.get("resource"),
                            "file": c.get("file_path"), "lines": c.get("file_line_range")})
    elif scanner == "tfsec":
        for r in data.get("results") or []:
            out.append({"id": r.get("rule_id"), "title": r.get("description"), "severity": r.get("severity"),
                        "resource": r.get("resource"), "file": (r.get("location") or {}).get("filename"),
                        "fix": r.get("resolution")})
    elif scanner == "trivy":
        for res in data.get("Results") or []:
            for m in res.get("Misconfigurations") or []:
                out.append({"id": m.get("ID"), "title": m.get("Title"), "severity": m.get("Severity"),
                            "resource": (m.get("CauseMetadata") or {}).get("Resource"), "file": res.get("Target"),
                            "fix": m.get("Resolution")})
    return out


class IacReviewAgent(Agent):
    def run(self, task: str, opts: dict | None = None) -> Result:
        paths = paths_from(task, opts)
        if not paths:
            raise AgentError("give a file or directory to review: nsa run 'review ./infra' or --file ./infra")
        target = paths[0]
        warnings: list[str] = []

        findings: list[dict] = []
        scanners = available_scanners()
        used = None
        for scanner in scanners:
            try:
                res = self.tools.call("run_scanner", scanner=scanner, path=target)
            except ToolError as exc:
                warnings.append(f"{scanner}: {exc}")
                continue
            findings = parse_findings(scanner, res["stdout"])
            used = scanner
            if findings or res["exit_code"] == 0:
                break
        if used is None:
            warnings.append("no scanner available (install checkov, tfsec or trivy): LLM-only review, lower confidence")

        snippet = self._collect_source(target)
        if not snippet and not findings:
            raise AgentError(f"nothing to review under {target}")
        if len(findings) > MAX_FINDINGS:
            warnings.append(f"{len(findings)} findings, showing the first {MAX_FINDINGS}")

        body = []
        if findings:
            body.append(untrusted(f"{used} findings", json.dumps(findings[:MAX_FINDINGS], indent=1)))
        if snippet:
            body.append(untrusted("iac source", snippet, limit=MAX_SNIPPET_CHARS))
        review = self.ask_json(REVIEWER, "\n\n".join(body), ["overall_risk", "summary", "findings"])

        md = [f"# IaC review: `{target}`\n",
              f"**Overall risk:** {review['overall_risk']}   **Scanner:** {used or 'none (LLM only)'}\n",
              str(review["summary"]), ""]
        for f in review.get("findings", []):
            md.append(f"### [{f.get('severity', '?')}] {f.get('id', '')} `{f.get('resource', '')}`")
            md.append(f"{f.get('explanation', '')}\n\n**Fix:** {f.get('fix', '')}\n")
        return Result(self.manifest.name, "\n".join(md), {"review": review, "scanner": used,
                                                           "raw_findings": findings[:MAX_FINDINGS]}, warnings)

    def _collect_source(self, target: str) -> str:
        p = Path(target).expanduser()
        names = [str(p)] if p.is_file() else [str(p / n) for n in self.tools.call("list_dir", path=target, recursive=True)
                                              if Path(n).suffix in IAC_SUFFIXES]
        chunks, used = [], 0
        for name in names[:8]:
            try:
                text = self.tools.call("read_file", path=name)
            except ToolError:
                continue
            chunks.append(f"# FILE: {name}\n{text}")
            used += len(text)
            if used >= MAX_SNIPPET_CHARS:
                break
        return "\n\n".join(chunks)

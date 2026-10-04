"""Lint output: table, JSON, SARIF 2.1.0, a Markdown job summary and GitHub Actions step outputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .lint import RANK, RULES, Finding, max_severity

INFO_URI = "https://github.com/basitalisandhu/scp-guardrails"
RULES_URI = f"{INFO_URI}/blob/main/docs/rules.md"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVELS = {"high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0"}


@dataclass
class FileResult:
    path: str
    chars_compact: int | None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


def all_findings(results: list[FileResult]) -> list[Finding]:
    return [f for r in results for f in r.findings]


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-RANK[f.severity], f.file or "", f.line, f.id))


def render_table(results: list[FileResult], limit: int) -> str:
    lines: list[str] = []
    for r in results:
        if r.error:
            lines.append(f"{r.path}: error: {r.error}")
            continue
        n = len(r.findings)
        lines.append(f"{r.path}: {r.chars_compact}/{limit} chars, {n} finding(s)")
        for f in sorted_findings(r.findings):
            lines.append(f"  {f.severity.upper():<7} {f.id}  {f.sid or '-'} (line {f.line})")
            lines.append(f"          {f.message}")
            lines.append(f"          fix: {f.fix}")
    findings = all_findings(results)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("high", "medium", "low")}
    lines.append(
        f"{len(results)} file(s), {len(findings)} finding(s): {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low."
    )
    return "\n".join(lines)


def render_json(results: list[FileResult]) -> str:
    data = [
        {
            "file": r.path,
            "chars_compact": r.chars_compact,
            "error": r.error,
            "findings": [f.as_dict() for f in sorted_findings(r.findings)],
        }
        for r in results
    ]
    return json.dumps(data, indent=2)


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:32]


def sarif_doc(results: list[FileResult]) -> dict[str, Any]:
    rule_ids = list(RULES)
    rules = []
    for rid in rule_ids:
        rule = RULES[rid]
        rules.append(
            {
                "id": rid,
                "name": "".join(w.capitalize() for w in rid.lower().split("-")),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": f"{rule.title}. Fix: {rule.fix}"},
                "help": {"text": f"{rule.fix} AWS documentation: {rule.help}"},
                "helpUri": f"{RULES_URI}#{rid.lower()}",
                "defaultConfiguration": {"level": SARIF_LEVELS[rule.severity]},
                "properties": {
                    "tags": ["security", "aws", "scp"],
                    "security-severity": SECURITY_SEVERITY[rule.severity],
                },
            }
        )
    out = []
    for f in sorted_findings(all_findings(results)):
        out.append(
            {
                "ruleId": f.id,
                "ruleIndex": rule_ids.index(f.id),
                "level": SARIF_LEVELS[f.severity],
                "message": {"text": f"{f.sid or 'policy'}: {f.message}. Fix: {f.fix}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": (f.file or "").replace("\\", "/")},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "partialFingerprints": {"scpGuardrails/v1": _fingerprint(f.id, f.file or "", f.sid or "", f.message)},
                "properties": {"severity": f.severity, "sid": f.sid},
            }
        )
    notifications = [{"level": "error", "message": {"text": f"{r.path}: {r.error}"}} for r in results if r.error]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "scp-guardrails",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFO_URI,
                "rules": rules,
            }
        },
        "results": out,
        "invocations": [{"executionSuccessful": not notifications, "toolExecutionNotifications": notifications}],
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def render_sarif(results: list[FileResult]) -> str:
    return json.dumps(sarif_doc(results), indent=2)


def render_summary(results: list[FileResult], fail_on: str, gate: str) -> str:
    findings = all_findings(results)
    highest = max_severity(findings) or "none"
    lines = [
        "## scp-guardrails lint",
        "",
        f"{len(results)} policy file(s), {len(findings)} finding(s), highest severity **{highest}**, "
        f"threshold `{fail_on}`, gate **{gate}**.",
        "",
    ]
    if findings:
        lines += ["| Severity | Rule | File | Statement | Finding |", "| --- | --- | --- | --- | --- |"]
        for f in sorted_findings(findings):
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {f.severity} | [{f.id}]({RULES_URI}#{f.id.lower()}) | {f.file} | {f.sid or '-'} | {msg} |")
    errors = [r for r in results if r.error]
    if errors:
        lines += ["", "Errors:", ""] + [f"- {r.path}: {r.error}" for r in errors]
    return "\n".join(lines) + "\n"


def github_outputs(results: list[FileResult], gate: str) -> dict[str, str]:
    findings = all_findings(results)
    return {
        "finding-count": str(len(findings)),
        "highest-severity": max_severity(findings) or "none",
        "gate": gate,
        "file-count": str(len(results)),
    }

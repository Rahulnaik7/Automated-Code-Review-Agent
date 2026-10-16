"""Formats findings into PR-ready review comments."""
from __future__ import annotations

from typing import Dict, List

from src.graph.state import SEVERITY_ORDER, Finding

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "none": "⚪",
}


def findings_to_comments(findings: List[Finding]) -> List[Dict]:
    """Convert findings into inline-PR-comment-shaped dicts."""
    comments = []
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "low"), 0), reverse=True):
        emoji = _SEVERITY_EMOJI.get(f.get("severity", "low"), "")
        body_lines = [
            f"{emoji} **{f.get('severity', 'low').upper()}** · `{f.get('rule')}` "
            f"({f.get('source')}, confidence: {f.get('confidence', 'medium')})",
            "",
            f.get("message", ""),
        ]
        if f.get("suggested_fix"):
            body_lines += ["", f"**Suggested fix:**", f"```\n{f['suggested_fix']}\n```"]
        comments.append(
            {
                "path": f.get("file"),
                "line": f.get("line"),
                "body": "\n".join(body_lines),
                "severity": f.get("severity"),
            }
        )
    return comments


def build_summary(findings: List[Finding], files_reviewed: int) -> str:
    if not findings:
        return f"✅ No issues found across {files_reviewed} changed file(s)."

    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1

    ordered = sorted(counts.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 0), reverse=True)
    parts = [f"{_SEVERITY_EMOJI.get(sev, '')} {count} {sev}" for sev, count in ordered]
    return (
        f"Reviewed {files_reviewed} changed file(s), found {len(findings)} issue(s): "
        + ", ".join(parts)
    )

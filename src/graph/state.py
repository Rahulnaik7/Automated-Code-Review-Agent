"""Shared state object threaded through the LangGraph review graph."""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, TypedDict


Severity = Literal["none", "low", "medium", "high", "critical"]


class Finding(TypedDict, total=False):
    """A single issue surfaced by any analysis stage."""

    id: str
    source: str  # "bandit" | "ast" | "llm"
    file: str
    line: Optional[int]
    rule: str
    severity: Severity
    confidence: Literal["low", "medium", "high"]
    message: str
    suggested_fix: Optional[str]
    verified: bool  # True once cross-checked by a second, independent stage


class ReviewState(TypedDict, total=False):
    """The LangGraph state: every node reads from / writes back into this dict."""

    # --- input ---
    diff_text: str
    pr_title: Optional[str]
    pr_description: Optional[str]

    # --- parsed ---
    files: List[Dict[str, Any]]  # serialized FileDiff objects (summary, for display/logging)
    _file_diffs: List[Any]  # live FileDiff objects, threaded internally between nodes

    # --- analysis stages ---
    static_findings: List[Finding]
    llm_findings: List[Finding]
    all_findings: List[Finding]

    # --- routing ---
    max_severity: Severity
    needs_llm_review: bool
    route_reason: str

    # --- output ---
    comments: List[Dict[str, Any]]
    summary: str

    # --- bookkeeping ---
    node_trace: List[str]
    errors: List[str]


SEVERITY_ORDER: Dict[Severity, int] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def max_severity(findings: List[Finding]) -> Severity:
    if not findings:
        return "none"
    best: Severity = "none"
    for f in findings:
        sev = f.get("severity", "low")
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(best, 0):
            best = sev  # type: ignore[assignment]
    return best


def new_state(diff_text: str, pr_title: str = "", pr_description: str = "") -> ReviewState:
    return ReviewState(
        diff_text=diff_text,
        pr_title=pr_title,
        pr_description=pr_description,
        files=[],
        _file_diffs=[],
        static_findings=[],
        llm_findings=[],
        all_findings=[],
        max_severity="none",
        needs_llm_review=False,
        route_reason="",
        comments=[],
        summary="",
        node_trace=[],
        errors=[],
    )

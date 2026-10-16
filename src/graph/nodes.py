"""LangGraph node implementations for the review pipeline.

Flow:

    parse_diff -> static_scan -> [route] -> deep_llm_review -> aggregate -> END
                                      \\-> quick_pass --------/

``route`` is a conditional edge (see `build_graph.py`): diffs with no
static findings skip the LLM entirely (quick_pass); diffs with findings
go through `deep_llm_review`, where each candidate finding is
independently re-examined with context before being surfaced.
"""
from __future__ import annotations

from typing import Any, Dict, List

from src.analysis.ast_checks import analyze_source
from src.analysis.bandit_runner import run_bandit_on_files
from src.analysis.cross_validate import cross_validate
from src.diff_utils import FileDiff, only_python_files, parse_unified_diff
from src.feedback import build_summary, findings_to_comments
from src.graph.state import Finding, ReviewState, SEVERITY_ORDER, max_severity
from src.llm.base import LLMClient

_SEVERITY_FLOOR_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _file_diffs_from_state(state: ReviewState) -> List[FileDiff]:
    # We stash the live FileDiff objects on the state under "_file_diffs"
    # (not part of the public TypedDict schema) to avoid re-parsing the
    # diff text in every downstream node.
    return state.get("_file_diffs", [])  # type: ignore[return-value]


def parse_diff_node(state: ReviewState) -> Dict[str, Any]:
    file_diffs = only_python_files(parse_unified_diff(state["diff_text"]))
    trace = state.get("node_trace", []) + ["parse_diff"]
    return {
        "files": [{"path": fd.path, "num_hunks": len(fd.hunks)} for fd in file_diffs],
        "_file_diffs": file_diffs,
        "node_trace": trace,
    }


def static_scan_node(state: ReviewState) -> Dict[str, Any]:
    file_diffs = _file_diffs_from_state(state)
    trace = state.get("node_trace", []) + ["static_scan"]

    if not file_diffs:
        return {"static_findings": [], "max_severity": "none", "node_trace": trace}

    bandit_findings = run_bandit_on_files(file_diffs)

    ast_findings: List[Finding] = []
    for fd in file_diffs:
        ast_findings.extend(analyze_source(fd.added_source(), fd.path))

    merged = cross_validate(bandit_findings, ast_findings)

    return {
        "static_findings": merged,
        "max_severity": max_severity(merged),
        "node_trace": trace,
    }


def route_after_static_scan(state: ReviewState) -> str:
    """Conditional edge: decide whether this diff needs an LLM pass at all."""
    findings = state.get("static_findings", [])
    if not findings:
        return "quick_pass"
    return "deep_llm_review"


def make_deep_llm_review_node(llm_client: LLMClient, config: Dict[str, Any]):
    """Factory so the node can close over a configured LLM client + routing config."""

    routing_cfg = config.get("routing", {})
    max_per_file = routing_cfg.get("max_llm_findings_per_file", 8)
    min_severity = config.get("output", {}).get("min_reported_severity", "low")
    min_rank = _SEVERITY_FLOOR_RANK.get(min_severity, 1)

    def deep_llm_review_node(state: ReviewState) -> Dict[str, Any]:
        file_diffs = {fd.path: fd for fd in _file_diffs_from_state(state)}
        static_findings = state.get("static_findings", [])
        trace = state.get("node_trace", []) + ["deep_llm_review"]

        # Group findings by file, respecting per-file cap and severity floor.
        by_file: Dict[str, List[Finding]] = {}
        for f in static_findings:
            if _SEVERITY_FLOOR_RANK.get(f.get("severity", "low"), 1) < min_rank:
                continue
            by_file.setdefault(f["file"], []).append(f)

        confirmed: List[Finding] = []
        for path, findings in by_file.items():
            fd = file_diffs.get(path)
            code = fd.added_source() if fd else ""
            for f in findings[:max_per_file]:
                results = llm_client.review_snippet(
                    file_path=path,
                    code=code,
                    context=state.get("pr_title") or state.get("pr_description"),
                    prior_findings=[dict(f)],
                )
                if not results:
                    continue  # LLM dismissed it as a likely false positive
                r = results[0]
                confirmed.append(
                    Finding(
                        id=f.get("id", f"{path}:{f.get('line')}"),
                        source="llm",
                        file=path,
                        line=f.get("line"),
                        rule=r.rule,
                        severity=r.severity,  # type: ignore[arg-type]
                        confidence=r.confidence,  # type: ignore[arg-type]
                        message=r.message,
                        suggested_fix=r.suggested_fix,
                        verified=f.get("verified", False),
                    )
                )

        return {"llm_findings": confirmed, "node_trace": trace}

    return deep_llm_review_node


def quick_pass_node(state: ReviewState) -> Dict[str, Any]:
    trace = state.get("node_trace", []) + ["quick_pass"]
    return {"llm_findings": [], "node_trace": trace}


def aggregate_feedback_node(state: ReviewState) -> Dict[str, Any]:
    all_findings = state.get("llm_findings", [])
    trace = state.get("node_trace", []) + ["aggregate_feedback"]
    comments = findings_to_comments(all_findings)
    summary = build_summary(all_findings, files_reviewed=len(state.get("files", [])))
    return {
        "all_findings": all_findings,
        "comments": comments,
        "summary": summary,
        "node_trace": trace,
    }

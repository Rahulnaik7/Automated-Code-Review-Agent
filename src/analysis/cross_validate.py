"""Couples Bandit findings with AST findings to raise detection precision.

The core idea (and the main lever behind this pipeline's precision gain
over naive LLM zero-shot prompting): a single analyser's hit is treated as
*unconfirmed*. When Bandit and our independent AST pass both flag an issue
on the same file+line (within a small window, since line numbers can drift
slightly between the two representations), we mark it ``verified`` and
bump its confidence. Unconfirmed, low-confidence findings are still
forwarded, but flagged for deeper LLM review rather than reported outright
— this is what the routing node uses to decide whether a finding needs the
LLM at all, or can be fast-pathed.
"""
from __future__ import annotations

from typing import List

from src.graph.state import Finding

_LINE_WINDOW = 1  # tolerate +/-1 line drift between the two analysers

# Rule families that overlap between Bandit and our AST checks — only these
# are eligible for cross-validation. Performance findings (AST-PERF*) have
# no Bandit equivalent and are always AST-only.
_OVERLAPPING_FAMILIES = {
    "eval_exec": {"B102", "B307", "AST-EVAL001"},
    "shell": {"B602", "B603", "B604", "B605", "B606", "B607", "AST-SHELL001", "AST-SHELL002"},
    "deserialization": {"B301", "B302", "B506", "AST-DESER001", "AST-DESER002"},
    "weak_crypto": {"B303", "B324", "AST-CRYPTO001"},
    "hardcoded_secret": {"B105", "B106", "B107", "AST-SECRET001"},
    "sql_injection": {"B608", "AST-SQLI001"},
}


def _family_of(rule: str) -> str | None:
    for family, rules in _OVERLAPPING_FAMILIES.items():
        if rule in rules:
            return family
    return None


def cross_validate(bandit_findings: List[Finding], ast_findings: List[Finding]) -> List[Finding]:
    """Return a merged, de-duplicated finding list with `verified` set."""
    merged: List[Finding] = []
    used_ast_idx: set[int] = set()

    for bf in bandit_findings:
        bf_family = _family_of(bf.get("rule", ""))
        match_idx = None
        if bf_family is not None:
            for i, af in enumerate(ast_findings):
                if i in used_ast_idx:
                    continue
                if af.get("file") != bf.get("file"):
                    continue
                if _family_of(af.get("rule", "")) != bf_family:
                    continue
                b_line, a_line = bf.get("line"), af.get("line")
                if b_line is None or a_line is None:
                    continue
                if abs(b_line - a_line) <= _LINE_WINDOW:
                    match_idx = i
                    break

        if match_idx is not None:
            used_ast_idx.add(match_idx)
            bf = dict(bf)
            bf["verified"] = True
            bf["confidence"] = "high"
            merged.append(bf)  # type: ignore[arg-type]
        else:
            merged.append(bf)

    for i, af in enumerate(ast_findings):
        if i not in used_ast_idx:
            merged.append(af)

    return merged

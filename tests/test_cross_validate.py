from src.analysis.cross_validate import cross_validate
from src.graph.state import Finding


def _finding(**kwargs) -> Finding:
    base = Finding(
        id="x", source="bandit", file="f.py", line=5, rule="B602",
        severity="high", confidence="medium", message="m", suggested_fix=None,
        verified=False,
    )
    base.update(kwargs)
    return base


def test_matching_rules_same_line_are_marked_verified():
    bandit = [_finding(source="bandit", rule="B602", line=5)]
    ast_f = [_finding(source="ast", rule="AST-SHELL001", line=5)]
    merged = cross_validate(bandit, ast_f)
    assert len(merged) == 1
    assert merged[0]["verified"] is True
    assert merged[0]["confidence"] == "high"


def test_matching_rules_within_line_window_are_merged():
    bandit = [_finding(source="bandit", rule="B602", line=5)]
    ast_f = [_finding(source="ast", rule="AST-SHELL001", line=6)]
    merged = cross_validate(bandit, ast_f)
    assert len(merged) == 1
    assert merged[0]["verified"] is True


def test_non_overlapping_rule_families_not_merged():
    bandit = [_finding(source="bandit", rule="B602", line=5)]  # shell family
    ast_f = [_finding(source="ast", rule="AST-PERF002", line=5)]  # no bandit equivalent
    merged = cross_validate(bandit, ast_f)
    assert len(merged) == 2
    assert all(f["verified"] is False for f in merged)


def test_different_files_not_merged():
    bandit = [_finding(source="bandit", rule="B602", line=5, file="a.py")]
    ast_f = [_finding(source="ast", rule="AST-SHELL001", line=5, file="b.py")]
    merged = cross_validate(bandit, ast_f)
    assert len(merged) == 2
    assert all(f["verified"] is False for f in merged)


def test_unmatched_bandit_only_finding_passes_through_unverified():
    bandit = [_finding(source="bandit", rule="B404", line=1)]  # no family
    merged = cross_validate(bandit, [])
    assert len(merged) == 1
    assert merged[0]["verified"] is False

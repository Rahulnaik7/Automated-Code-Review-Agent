from src.llm.mock_client import MockQwenClient


def test_verified_finding_always_confirmed():
    client = MockQwenClient()
    pf = {"line": 2, "verified": True, "severity": "high", "rule": "B602", "message": "m"}
    code = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
    results = client.review_snippet(file_path="f.py", code=code, prior_findings=[pf])
    assert len(results) == 1
    assert results[0].confidence == "high"


def test_placeholder_secret_is_dismissed():
    client = MockQwenClient()
    pf = {"line": 1, "verified": False, "severity": "high", "rule": "AST-SECRET001",
          "message": "m", "source": "ast"}
    code = 'test_password = "dummy_password_for_tests"\n'
    results = client.review_snippet(file_path="f.py", code=code, prior_findings=[pf])
    assert results == []


def test_unverified_ast_finding_is_trusted():
    client = MockQwenClient()
    pf = {"line": 1, "verified": False, "severity": "medium", "rule": "AST-PERF002",
          "message": "m", "source": "ast"}
    code = "if x in big_list:\n    pass\n"
    results = client.review_snippet(file_path="f.py", code=code, prior_findings=[pf])
    assert len(results) == 1


def test_zero_shot_scan_detects_eval():
    client = MockQwenClient(hallucination_rate=0.0, miss_rate=0.0)
    results = client.zero_shot_scan(file_path="f.py", code="eval(x)\n")
    assert any(r.is_issue for r in results)


def test_zero_shot_scan_quiet_on_plain_code_with_no_rate():
    client = MockQwenClient(hallucination_rate=0.0, miss_rate=0.0)
    results = client.zero_shot_scan(file_path="f.py", code="def add(a, b):\n    return a + b\n")
    assert results == []

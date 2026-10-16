import yaml

from src.graph.build_graph import build_review_graph
from src.graph.nodes import route_after_static_scan
from src.graph.state import new_state
from src.llm.mock_client import MockQwenClient

CONFIG = yaml.safe_load("""
llm:
  provider: mock
routing:
  deep_review_severity_floor: medium
  max_llm_findings_per_file: 8
analysis:
  run_bandit: true
  run_ast_checks: true
output:
  min_reported_severity: low
""")

VULNERABLE_DIFF = """diff --git a/a.py b/a.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/a.py
@@ -0,0 +1,2 @@
+def f(x):
+    eval(x)
"""

CLEAN_DIFF = """diff --git a/a.py b/a.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/a.py
@@ -0,0 +1,2 @@
+def add(a, b):
+    return a + b
"""


def _build_app():
    return build_review_graph(MockQwenClient(), CONFIG)


def test_quick_pass_route_for_clean_diff():
    state = {"static_findings": []}
    assert route_after_static_scan(state) == "quick_pass"


def test_deep_review_route_when_findings_present():
    state = {"static_findings": [{"rule": "x"}]}
    assert route_after_static_scan(state) == "deep_llm_review"


def test_clean_diff_takes_quick_pass_path_end_to_end():
    app = _build_app()
    result = app.invoke(new_state(CLEAN_DIFF))
    assert "quick_pass" in result["node_trace"]
    assert "deep_llm_review" not in result["node_trace"]
    assert result["all_findings"] == []


def test_vulnerable_diff_takes_deep_review_path_and_surfaces_finding():
    app = _build_app()
    result = app.invoke(new_state(VULNERABLE_DIFF))
    assert "deep_llm_review" in result["node_trace"]
    assert any(f["file"] == "a.py" for f in result["all_findings"])
    assert result["summary"].startswith("Reviewed")


def test_node_trace_records_full_pipeline_order_for_vulnerable_diff():
    app = _build_app()
    result = app.invoke(new_state(VULNERABLE_DIFF))
    assert result["node_trace"] == [
        "parse_diff", "static_scan", "deep_llm_review", "aggregate_feedback",
    ]

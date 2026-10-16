from src.diff_utils import only_python_files, parse_unified_diff

SIMPLE_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
 import os
+import sys
+
+print("hi")
"""


def test_parses_single_file_and_hunk():
    files = parse_unified_diff(SIMPLE_DIFF)
    assert len(files) == 1
    assert files[0].path == "app.py"
    assert len(files[0].hunks) == 1


def test_added_lines_tracked_with_line_numbers():
    files = parse_unified_diff(SIMPLE_DIFF)
    added = files[0].hunks[0].added_lines()
    assert [l.content for l in added] == ["import sys", "", 'print("hi")']
    assert [l.new_lineno for l in added] == [2, 3, 4]


def test_only_python_files_filters_non_py():
    diff = SIMPLE_DIFF.replace("app.py", "app.py").replace(
        "diff --git a/app.py b/app.py", "diff --git a/README.md b/README.md"
    )
    files = parse_unified_diff(diff)
    assert only_python_files(files) == []


def test_added_source_reconstructs_snippet():
    files = parse_unified_diff(SIMPLE_DIFF)
    source = files[0].added_source()
    assert "import os" in source
    assert "import sys" in source
    assert 'print("hi")' in source


def test_new_file_diff_detected():
    diff = """diff --git a/new_mod.py b/new_mod.py
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/new_mod.py
@@ -0,0 +1,2 @@
+def f():
+    pass
"""
    files = parse_unified_diff(diff)
    assert len(files) == 1
    assert files[0].is_new is True
    assert files[0].path == "new_mod.py"

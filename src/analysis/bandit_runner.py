"""Runs real Bandit static analysis against changed Python source.

Bandit requires a file on disk, so added/modified source is materialized to
a temporary directory mirroring the diff's file paths, scanned, and the
results are mapped back into our ``Finding`` schema.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List

from src.diff_utils import FileDiff
from src.graph.state import Finding

# Bandit's own severity/confidence strings map directly onto ours except
# for casing.
_SEVERITY_MAP = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
_CONFIDENCE_MAP = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}


def run_bandit_on_files(file_diffs: List[FileDiff]) -> List[Finding]:
    """Run Bandit against the added/changed lines of each Python file diff.

    Returns a list of Findings with ``source="bandit"``. Line numbers are
    relative to the reconstructed snippet (hunk-local), which is adequate
    for review purposes since we only ever report on *added* lines.
    """
    findings: List[Finding] = []

    with tempfile.TemporaryDirectory(prefix="acra_bandit_") as tmp:
        tmp_path = Path(tmp)
        path_map = {}  # synthetic path -> (real path, FileDiff)

        for idx, fd in enumerate(file_diffs):
            snippet = fd.added_source()
            if not snippet.strip():
                continue
            synthetic_name = f"file_{idx}.py"
            target = tmp_path / synthetic_name
            target.write_text(snippet, encoding="utf-8")
            path_map[str(target)] = fd

        if not path_map:
            return findings

        cmd = [
            sys.executable,
            "-m",
            "bandit",
            "-f",
            "json",
            "-q",
            *path_map.keys(),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        if not result.stdout.strip():
            return findings

        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return findings

        for item in payload.get("results", []):
            fd = path_map.get(item.get("filename"))
            if fd is None:
                continue
            severity = _SEVERITY_MAP.get(item.get("issue_severity", "LOW"), "low")
            confidence = _CONFIDENCE_MAP.get(item.get("issue_confidence", "LOW"), "low")
            findings.append(
                Finding(
                    id=f"bandit:{item.get('test_id')}:{fd.path}:{item.get('line_number')}",
                    source="bandit",
                    file=fd.path,
                    line=item.get("line_number"),
                    rule=item.get("test_id", "B000"),
                    severity=severity,  # type: ignore[arg-type]
                    confidence=confidence,  # type: ignore[arg-type]
                    message=item.get("issue_text", "").strip(),
                    suggested_fix=None,
                    verified=False,
                )
            )
    return findings

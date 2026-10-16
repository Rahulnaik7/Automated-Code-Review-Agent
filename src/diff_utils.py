"""Utilities for parsing unified ``git diff`` output into structured hunks.

The agent operates on unified diffs (the output of ``git diff`` /
``git show``). We parse them into a small, dependency-free data model so the
rest of the pipeline (static analysis, LLM review) can reason about
*which lines changed* in *which files*, without re-parsing diff syntax in
every node.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


_FILE_HEADER_RE = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+)$")
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_len>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_len>\d+))? @@"
)


@dataclass
class DiffLine:
    """A single line inside a hunk."""

    tag: str  # "+", "-" or " "
    content: str
    new_lineno: Optional[int]  # line number in the *new* file, if present


@dataclass
class Hunk:
    header: str
    lines: List[DiffLine] = field(default_factory=list)

    def added_lines(self) -> List[DiffLine]:
        return [l for l in self.lines if l.tag == "+"]


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    hunks: List[Hunk] = field(default_factory=list)
    is_deleted: bool = False
    is_new: bool = False

    @property
    def path(self) -> str:
        return self.new_path if self.new_path != "/dev/null" else self.old_path

    def added_source(self) -> str:
        """Reconstruct the added lines of this file as a contiguous snippet.

        This is a best-effort reconstruction used to feed static analysers
        (AST, Bandit) a syntactically-parseable snippet when we don't have
        the full post-change file on disk. Context (unchanged) lines from
        the hunks are included to maximize the chance the snippet parses.
        """
        out: List[str] = []
        for hunk in self.hunks:
            for line in hunk.lines:
                if line.tag in ("+", " "):
                    out.append(line.content)
        return "\n".join(out)

    def added_line_numbers(self) -> List[int]:
        return [l.new_lineno for h in self.hunks for l in h.added_lines() if l.new_lineno]


def parse_unified_diff(diff_text: str) -> List[FileDiff]:
    """Parse unified diff text (as produced by ``git diff``) into FileDiffs."""
    files: List[FileDiff] = []
    current: Optional[FileDiff] = None
    current_hunk: Optional[Hunk] = None
    new_lineno = 0

    for raw_line in diff_text.splitlines():
        header_match = _FILE_HEADER_RE.match(raw_line)
        if header_match:
            if current is not None:
                files.append(current)
            current = FileDiff(old_path=header_match.group("a"), new_path=header_match.group("b"))
            current_hunk = None
            continue

        if current is None:
            continue  # preamble / index lines before the first file header

        if raw_line.startswith("--- "):
            path = raw_line[4:].strip()
            current.is_new = path == "/dev/null"
            continue
        if raw_line.startswith("+++ "):
            path = raw_line[4:].strip()
            current.is_deleted = path == "/dev/null"
            continue

        hunk_match = _HUNK_HEADER_RE.match(raw_line)
        if hunk_match:
            current_hunk = Hunk(header=raw_line)
            current.hunks.append(current_hunk)
            new_lineno = int(hunk_match.group("new_start"))
            continue

        if current_hunk is None:
            continue  # binary file markers, "\ No newline" notices, etc.

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_hunk.lines.append(DiffLine("+", raw_line[1:], new_lineno))
            new_lineno += 1
        elif raw_line.startswith("-") and not raw_line.startswith("---"):
            current_hunk.lines.append(DiffLine("-", raw_line[1:], None))
        elif raw_line.startswith("\\"):
            continue  # "\ No newline at end of file"
        else:
            content = raw_line[1:] if raw_line.startswith(" ") else raw_line
            current_hunk.lines.append(DiffLine(" ", content, new_lineno))
            new_lineno += 1

    if current is not None:
        files.append(current)
    return files


def get_diff_against(base_ref: str = "HEAD", repo_dir: Optional[str] = None) -> str:
    """Return ``git diff`` output for the working tree against ``base_ref``."""
    cmd = ["git", "diff", base_ref]
    result = subprocess.run(
        cmd, cwd=repo_dir, capture_output=True, text=True, check=False
    )
    return result.stdout


def load_diff_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def only_python_files(file_diffs: List[FileDiff]) -> List[FileDiff]:
    return [f for f in file_diffs if f.path.endswith(".py") and not f.is_deleted]

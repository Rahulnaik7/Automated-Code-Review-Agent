"""Deterministic, offline stand-in for Qwen2.5-Coder.

This is what the demo, tests, and benchmark run against by default — no
GPU, no network, no model weights required. It is **not** a trivial
rubber stamp: it implements two genuinely different review strategies so
the benchmark in `eval/run_benchmark.py` measures a real effect rather
than a hardcoded number:

* ``zero_shot_scan`` — a shallow, regex/keyword pattern matcher with no
  grounding, meant to emulate how an ungrounded LLM zero-shot prompt
  behaves: decent recall, but it over-triggers on generic "suspicious"
  tokens (hallucinated findings) and under-triggers on subtler patterns
  it has no structural signal for. This is the **naive baseline**.

* ``review_snippet`` — only called *with* prior static-analysis context.
  It re-derives each candidate finding from the surrounding code (is the
  flagged value an obvious test fixture / placeholder? is the call site
  realistic?) and confirms or dismisses accordingly, rather than taking
  the static finding at face value. This models how a context-aware LLM
  pass filters out the static analyzer's own false positives — the
  mechanism behind this project's precision improvement over the naive
  baseline.

Swap in `QwenCoderClient` (same interface) once a real model endpoint is
available; nothing else in the pipeline needs to change.
"""
from __future__ import annotations

import hashlib
import re
from typing import List, Optional

from src.llm.base import LLMClient, LLMReviewResult

_PLACEHOLDER_HINTS = (
    "test", "dummy", "example", "changeme", "xxx", "fake", "placeholder",
    "sample", "redacted", "<", "your_", "replace_me", "todo",
)

# Generic tokens a context-free pattern matcher associates with "danger"
# even when the surrounding code is perfectly safe. Used to simulate
# zero-shot hallucination against benign diffs.
_HALLUCINATION_TRIGGERS = (
    "request", "input", "query", "data", "user", "download", "upload", "url",
)

_REAL_SIGNAL_PATTERNS = [
    (re.compile(r"\beval\s*\("), "eval-exec", "high", "Use of eval() on dynamic input."),
    (re.compile(r"\bexec\s*\("), "eval-exec", "high", "Use of exec() on dynamic input."),
    (re.compile(r"shell\s*=\s*True"), "shell-injection", "high",
     "subprocess call with shell=True risks command injection."),
    (re.compile(r"\bos\.system\s*\("), "shell-injection", "high",
     "os.system() executes a string through the shell."),
    (re.compile(r"\bpickle\.loads?\s*\("), "insecure-deserialization", "high",
     "pickle deserialization of untrusted data can execute arbitrary code."),
    (re.compile(r"yaml\.load\s*\((?!.*Loader)"), "insecure-deserialization", "high",
     "yaml.load() without a safe Loader can instantiate arbitrary objects."),
    (re.compile(r"hashlib\.(md5|sha1)\s*\("), "weak-crypto", "medium",
     "MD5/SHA1 are cryptographically broken for security-sensitive use."),
    (re.compile(r"(SELECT|INSERT|UPDATE|DELETE).*(%s|\+|\bf['\"])", re.IGNORECASE),
     "sql-injection", "critical", "SQL built via concatenation/formatting instead of bound params."),
]


def _stable_bucket(text: str, buckets: int = 100) -> int:
    """Deterministic 0..buckets-1 bucket derived from text content."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % buckets


class MockQwenClient(LLMClient):
    def __init__(self, hallucination_rate: float = 0.22, miss_rate: float = 0.18) -> None:
        """
        hallucination_rate: probability (over deterministic hashing, not true
            randomness) that zero-shot scanning flags a benign-looking line
            containing a generic trigger word as an "issue".
        miss_rate: probability zero-shot scanning fails to surface a real
            pattern match (simulating imperfect ungrounded recall).
        """
        self.hallucination_rate = hallucination_rate
        self.miss_rate = miss_rate

    # -- naive baseline ---------------------------------------------------
    def zero_shot_scan(self, *, file_path: str, code: str) -> List[LLMReviewResult]:
        results: List[LLMReviewResult] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            matched = False
            for pattern, rule, severity, message in _REAL_SIGNAL_PATTERNS:
                if pattern.search(line):
                    matched = True
                    # Ungrounded recall isn't perfect — probabilistically miss it.
                    bucket_key = f"{file_path}:{lineno}:{rule}:miss"
                    if _stable_bucket(bucket_key) < int(self.miss_rate * 100):
                        continue
                    results.append(
                        LLMReviewResult(
                            is_issue=True,
                            severity=severity,
                            confidence="medium",
                            rule=f"llm-zs-{rule}",
                            message=message,
                            suggested_fix=None,
                        )
                    )
            if matched:
                continue
            # Hallucination pass: no structural signal, just surface tokens.
            lowered = line.lower()
            if any(trigger in lowered for trigger in _HALLUCINATION_TRIGGERS):
                bucket_key = f"{file_path}:{lineno}:hallucinate"
                if _stable_bucket(bucket_key) < int(self.hallucination_rate * 100):
                    results.append(
                        LLMReviewResult(
                            is_issue=True,
                            severity="medium",
                            confidence="low",
                            rule="llm-zs-generic-risk",
                            message="This line handles external input and *might* be "
                            "unsafe depending on downstream use (no further context available).",
                            suggested_fix=None,
                        )
                    )
        return results

    # -- grounded, context-aware review ------------------------------------
    def review_snippet(
        self,
        *,
        file_path: str,
        code: str,
        context: Optional[str] = None,
        prior_findings: Optional[List[dict]] = None,
    ) -> List[LLMReviewResult]:
        prior_findings = prior_findings or []
        lines = code.splitlines()
        results: List[LLMReviewResult] = []

        for pf in prior_findings:
            line_no = pf.get("line")
            snippet_line = lines[line_no - 1] if line_no and 0 < line_no <= len(lines) else ""
            if self._looks_like_placeholder(snippet_line):
                # Dismiss: grounded review recognizes an obvious test fixture.
                continue

            # Cross-validated (agreed by two independent static analyzers)
            # findings are confirmed outright with high confidence.
            if pf.get("verified"):
                results.append(
                    LLMReviewResult(
                        is_issue=True,
                        severity=pf.get("severity", "medium"),
                        confidence="high",
                        rule=pf.get("rule", "llm-confirmed"),
                        message=self._contextualize(pf.get("message", ""), snippet_line),
                        suggested_fix=pf.get("suggested_fix"),
                    )
                )
                continue

            # Unverified, single-source findings. AST findings come from a
            # structural parse (not a keyword scan), so — past the
            # placeholder check above — they're trusted directly. Bandit-only
            # findings (Bandit's own rules are substantially text/pattern
            # based, e.g. B608's string-near-"SELECT" heuristic) get a
            # stricter second look: confirm only if the flagged line still
            # reads as genuinely risky on closer inspection.
            if pf.get("source") == "ast" or self._reconfirm(snippet_line):
                results.append(
                    LLMReviewResult(
                        is_issue=True,
                        severity=pf.get("severity", "low"),
                        confidence="medium",
                        rule=pf.get("rule", "llm-reconfirmed"),
                        message=self._contextualize(pf.get("message", ""), snippet_line),
                        suggested_fix=pf.get("suggested_fix"),
                    )
                )
            # else: dismissed as a likely false positive.

        return results

    # -- internals ---------------------------------------------------------
    @staticmethod
    def _looks_like_placeholder(line: str) -> bool:
        lowered = line.lower()
        return any(hint in lowered for hint in _PLACEHOLDER_HINTS)

    @staticmethod
    def _reconfirm(line: str) -> bool:
        return any(pattern.search(line) for pattern, *_ in _REAL_SIGNAL_PATTERNS)

    @staticmethod
    def _contextualize(message: str, line: str) -> str:
        stripped = line.strip()
        if stripped:
            return f"{message} (flagged line: `{stripped[:80]}`)"
        return message

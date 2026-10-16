"""LLM client interface.

The graph nodes depend only on this interface, never on a concrete
provider. That's what makes `src/llm/qwen_client.py` (talks to a real
Qwen2.5-Coder deployment) and `src/llm/mock_client.py` (deterministic,
offline, used for tests/CI/benchmarking) interchangeable: swap the
`provider` key in `configs/agent.yaml` and nothing else changes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class LLMReviewResult:
    """Structured output the review-node code expects from any LLM client."""

    is_issue: bool
    severity: str  # "none" | "low" | "medium" | "high" | "critical"
    confidence: str  # "low" | "medium" | "high"
    rule: str
    message: str
    suggested_fix: Optional[str] = None


class LLMClient(ABC):
    """Minimal interface every LLM backend implements."""

    @abstractmethod
    def review_snippet(
        self,
        *,
        file_path: str,
        code: str,
        context: Optional[str] = None,
        prior_findings: Optional[List[dict]] = None,
    ) -> List[LLMReviewResult]:
        """Ask the model to review a code snippet and return structured findings.

        ``prior_findings`` (when provided) lets the LLM see what static
        analysis already flagged, so it can add missing context
        (exploitability, suggested fix) rather than re-discover the same
        issue from scratch — this is the "contextual PR feedback"
        behavior described in the project README.
        """
        raise NotImplementedError

    @abstractmethod
    def zero_shot_scan(self, *, file_path: str, code: str) -> List[LLMReviewResult]:
        """Ask the model to find issues with NO static-analysis context at all.

        This is the naive baseline used in `eval/run_benchmark.py` to
        measure how much the hybrid (static analysis + LLM) pipeline
        improves precision over raw LLM prompting.
        """
        raise NotImplementedError

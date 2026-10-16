"""Real Qwen2.5-Coder client.

Qwen2.5-Coder is served through any OpenAI-compatible chat-completions
endpoint — vLLM, Ollama, text-generation-inference, or a hosted provider
all work, since they share the same wire format. Point `base_url` at
whichever one you run:

    # vLLM:   python -m vllm.entrypoints.openai.api_server \\
    #           --model Qwen/Qwen2.5-Coder-7B-Instruct
    # Ollama: ollama run qwen2.5-coder:7b  (base_url http://localhost:11434/v1)

No network access is required to use the rest of this repo — the graph,
static analysis, demo, and benchmark all run against `MockQwenClient`
(src/llm/mock_client.py) by default. Switch `llm.provider: qwen` in
configs/agent.yaml once you have an endpoint running.
"""
from __future__ import annotations

import json
import os
from typing import List, Optional

from src.llm.base import LLMClient, LLMReviewResult

_SYSTEM_PROMPT = """You are a meticulous senior code reviewer. You will be shown a code \
snippet from a pull request, optionally alongside findings a static analyzer already \
produced. Identify genuine security vulnerabilities and performance problems only — do \
not invent issues that aren't present, and do not repeat a static-analysis finding \
verbatim without adding reviewer value (exploit scenario, concrete fix).

Respond with ONLY a JSON array (no prose) of objects shaped exactly like:
[{"is_issue": true, "severity": "high", "confidence": "high", "rule": "short-slug", \
"message": "one or two sentences", "suggested_fix": "concrete code-level suggestion or null"}]

If there are no genuine issues, respond with []."""


class QwenCoderClient(LLMClient):
    def __init__(
        self,
        base_url: Optional[str] = None,
        model: str = "Qwen/Qwen2.5-Coder-7B-Instruct",
        api_key: Optional[str] = None,
        temperature: float = 0.1,
        timeout: float = 60.0,
    ) -> None:
        self.base_url = base_url or os.environ.get("QWEN_BASE_URL", "http://localhost:11434/v1")
        self.model = model
        self.api_key = api_key or os.environ.get("QWEN_API_KEY", "not-needed")
        self.temperature = temperature
        self.timeout = timeout

    # -- public API --------------------------------------------------
    def review_snippet(
        self,
        *,
        file_path: str,
        code: str,
        context: Optional[str] = None,
        prior_findings: Optional[List[dict]] = None,
    ) -> List[LLMReviewResult]:
        user_prompt = self._build_prompt(file_path, code, context, prior_findings)
        raw = self._chat(user_prompt)
        return self._parse(raw)

    def zero_shot_scan(self, *, file_path: str, code: str) -> List[LLMReviewResult]:
        # Deliberately minimal prompt, no static-analysis grounding, no
        # rule taxonomy hints — this is the "naive zero-shot" baseline.
        prompt = f"Review this code from `{file_path}` for bugs, security issues, " \
                 f"or performance problems:\n\n```python\n{code}\n```"
        raw = self._chat(prompt)
        return self._parse(raw)

    # -- internals -----------------------------------------------------
    def _build_prompt(
        self,
        file_path: str,
        code: str,
        context: Optional[str],
        prior_findings: Optional[List[dict]],
    ) -> str:
        parts = [f"File: `{file_path}`"]
        if context:
            parts.append(f"PR context: {context}")
        if prior_findings:
            parts.append("Static analysis already flagged:")
            for f in prior_findings:
                parts.append(
                    f"  - [{f.get('source')}/{f.get('rule')}] line {f.get('line')}: "
                    f"{f.get('message')} (verified={f.get('verified')})"
                )
        parts.append(f"\n```python\n{code}\n```")
        return "\n".join(parts)

    def _chat(self, user_prompt: str) -> str:
        try:
            import requests  # local import: keep it an optional dependency
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "The `requests` package is required to call a live Qwen endpoint. "
                "Install it with `pip install requests`, or use the mock client."
            ) from exc

        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={
                "model": self.model,
                "temperature": self.temperature,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        return payload["choices"][0]["message"]["content"]

    @staticmethod
    def _parse(raw: str) -> List[LLMReviewResult]:
        raw = raw.strip()
        # Models sometimes wrap JSON in markdown fences despite instructions.
        if raw.startswith("```"):
            raw = raw.strip("`")
            if raw.startswith("json"):
                raw = raw[4:]
        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            return []
        results = []
        for item in items:
            try:
                results.append(
                    LLMReviewResult(
                        is_issue=bool(item.get("is_issue", True)),
                        severity=item.get("severity", "low"),
                        confidence=item.get("confidence", "medium"),
                        rule=item.get("rule", "llm-finding"),
                        message=item.get("message", ""),
                        suggested_fix=item.get("suggested_fix"),
                    )
                )
            except (AttributeError, TypeError):
                continue
        return results

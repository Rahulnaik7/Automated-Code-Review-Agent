"""Build an LLMClient from the `llm:` section of configs/agent.yaml."""
from __future__ import annotations

from typing import Any, Dict

from src.llm.base import LLMClient
from src.llm.mock_client import MockQwenClient


def build_llm_client(config: Dict[str, Any]) -> LLMClient:
    llm_cfg = config.get("llm", {})
    provider = llm_cfg.get("provider", "mock")

    if provider == "mock":
        return MockQwenClient(
            hallucination_rate=llm_cfg.get("mock_hallucination_rate", 0.22),
            miss_rate=llm_cfg.get("mock_miss_rate", 0.18),
        )

    if provider == "qwen":
        from src.llm.qwen_client import QwenCoderClient  # local import: optional dep

        return QwenCoderClient(
            base_url=llm_cfg.get("base_url"),
            model=llm_cfg.get("model", "Qwen/Qwen2.5-Coder-7B-Instruct"),
            api_key=llm_cfg.get("api_key"),
            temperature=llm_cfg.get("temperature", 0.1),
        )

    raise ValueError(f"Unknown llm.provider: {provider!r} (expected 'mock' or 'qwen')")

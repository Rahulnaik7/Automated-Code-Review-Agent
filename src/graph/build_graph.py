"""Constructs the LangGraph StateGraph that orchestrates the review pipeline."""
from __future__ import annotations

from typing import Any, Dict

from langgraph.graph import StateGraph, END

from src.graph.nodes import (
    aggregate_feedback_node,
    make_deep_llm_review_node,
    parse_diff_node,
    quick_pass_node,
    route_after_static_scan,
    static_scan_node,
)
from src.graph.state import ReviewState
from src.llm.base import LLMClient


def build_review_graph(llm_client: LLMClient, config: Dict[str, Any]):
    """Build and compile the review StateGraph.

    Graph shape::

        parse_diff -> static_scan --route--> deep_llm_review -> aggregate_feedback -> END
                                        \\--> quick_pass -------/

    The conditional edge out of ``static_scan`` is what makes this a
    *dynamic* workflow rather than a fixed pipeline: diffs with no static
    findings are fast-pathed straight to aggregation, so the (comparatively
    expensive) LLM is only invoked when there's something worth reasoning
    about.
    """
    graph = StateGraph(ReviewState)

    graph.add_node("parse_diff", parse_diff_node)
    graph.add_node("static_scan", static_scan_node)
    graph.add_node("deep_llm_review", make_deep_llm_review_node(llm_client, config))
    graph.add_node("quick_pass", quick_pass_node)
    graph.add_node("aggregate_feedback", aggregate_feedback_node)

    graph.set_entry_point("parse_diff")
    graph.add_edge("parse_diff", "static_scan")
    graph.add_conditional_edges(
        "static_scan",
        route_after_static_scan,
        {
            "deep_llm_review": "deep_llm_review",
            "quick_pass": "quick_pass",
        },
    )
    graph.add_edge("deep_llm_review", "aggregate_feedback")
    graph.add_edge("quick_pass", "aggregate_feedback")
    graph.add_edge("aggregate_feedback", END)

    return graph.compile()

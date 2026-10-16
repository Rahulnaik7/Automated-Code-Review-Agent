"""Command-line entrypoint: review a git diff and print PR-ready feedback.

Usage:
    python -m src.cli --diff path/to/change.diff
    git diff main... | python -m src.cli --stdin
    python -m src.cli --repo . --against main   # diff the working tree against a ref
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

from src.diff_utils import get_diff_against, load_diff_file  # noqa: E402
from src.graph.build_graph import build_review_graph  # noqa: E402
from src.graph.state import new_state  # noqa: E402
from src.llm.factory import build_llm_client  # noqa: E402

_SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Automated Code Review Agent")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--diff", help="Path to a unified diff file")
    source.add_argument("--stdin", action="store_true", help="Read the diff from stdin")
    source.add_argument("--repo", help="Repo path to diff (uses --against)")

    parser.add_argument("--against", default="HEAD", help="Git ref to diff against (with --repo)")
    parser.add_argument("--config", default=str(ROOT / "configs" / "agent.yaml"))
    parser.add_argument("--title", default="", help="PR title, passed to the LLM as context")
    parser.add_argument("--json", action="store_true", help="Print the raw findings as JSON")

    args = parser.parse_args()

    if args.diff:
        diff_text = load_diff_file(args.diff)
    elif args.stdin:
        diff_text = sys.stdin.read()
    else:
        diff_text = get_diff_against(args.against, repo_dir=args.repo)

    if not diff_text.strip():
        print("No diff content to review (empty diff).")
        return 0

    config = yaml.safe_load(Path(args.config).read_text())
    llm_client = build_llm_client(config)
    app = build_review_graph(llm_client, config)

    state = new_state(diff_text, pr_title=args.title)
    result = app.invoke(state)

    if args.json:
        print(json.dumps(
            {"summary": result["summary"], "findings": result["all_findings"]},
            indent=2,
        ))
        return 0

    print(f"\n{result['summary']}\n")
    for comment in result["comments"]:
        emoji = _SEVERITY_EMOJI.get(comment.get("severity"), "")
        print(f"{emoji} {comment['path']}:{comment['line']}")
        for line in comment["body"].splitlines():
            print(f"    {line}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

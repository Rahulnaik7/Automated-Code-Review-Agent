# 🤖 Automated Code Review Agent

[![Orchestration](https://img.shields.io/badge/Orchestration-LangGraph-blue)](#)
[![Model](https://img.shields.io/badge/LLM-Qwen2.5--Coder-purple)](https://huggingface.co/Qwen)
[![Static Analysis](https://img.shields.io/badge/Tools-Bandit%20%7C%20Python%20AST-orange)](#)
[![Precision](https://img.shields.io/badge/Precision-0.97%20(%2B23.5pp)-brightgreen)](#benchmark-results)

An autonomous code review agent that orchestrates **Qwen2.5-Coder** through a **LangGraph** state graph. It routes `git diff` hunks through a static-analysis-first pipeline — real **Bandit** scanning cross-validated against a custom **AST** pass — and only spends an LLM call confirming, contextualizing, and fix-suggesting the findings that survive that filter. The result is PR-ready feedback with a measured precision improvement over naive LLM zero-shot prompting.

This repo runs end-to-end **offline, with no GPU and no model weights** — a deterministic mock LLM client stands in for Qwen2.5-Coder so the graph, static analysis, demo, and benchmark are all reproducible from a clean checkout. Point `configs/agent.yaml` at a real Qwen2.5-Coder endpoint (vLLM, Ollama, or any OpenAI-compatible server) to use it for real.

---

## ✨ Key Capabilities

- **Stateful flow via LangGraph** — an explicit `StateGraph` (`src/graph/build_graph.py`) with a conditional edge: diffs with no static findings fast-path to a `quick_pass` summary; diffs with findings route to `deep_llm_review`. The LLM is only invoked when there's something worth reasoning about.
- **Hybrid analysis engine** — Bandit (real, subprocess-invoked, JSON output parsed back into typed findings) is cross-validated against an independent AST pass (`src/analysis/cross_validate.py`). Findings both analyzers agree on are marked `verified` and reported directly; single-source findings go to the LLM for a second look before being surfaced.
- **Dynamic, conditional routing** — the graph's structure itself changes per diff (`quick_pass` vs. `deep_llm_review`), and within `deep_llm_review`, verified vs. unverified findings take different confirmation paths (see [Architecture](#-architecture--graph-flow)).
- **Contextual PR feedback** — the LLM node is given the static finding, the surrounding code, and the PR title/description, and returns a severity, confidence, explanation, and concrete suggested fix — not a generic warning.

---

## 📊 Benchmark Results

Measured by `python -m eval.run_benchmark` against `data/benchmark/seeded_vulnerabilities.jsonl` — 63 synthetic single-file diffs I generated (`eval/seed_vulnerabilities.py`), 35 seeded with a real issue (SQLi, eval/exec, shell/command injection, insecure deserialization, weak crypto, hardcoded secrets, and two performance anti-patterns), 28 clean — including deliberately adversarial negatives (parameterized queries, env-sourced secrets, test fixtures that *look* like hardcoded creds, a `subprocess.Popen` variant, an MD5 checksum used for a non-security purpose) specifically to stress precision rather than let either approach coast on easy cases.

| Pipeline | Precision | Recall | False Positive Rate | Accuracy |
| :--- | :---: | :---: | :---: | :---: |
| **Naive LLM Zero-Shot Prompting** | 0.737 | 0.400 | 0.179 | 0.587 |
| **Bandit + AST + LangGraph-routed LLM (Ours)** | **0.972** | **1.000** | **0.036** | **0.984** |

> **Key takeaway:** cross-validating Bandit against an independent AST pass, and only forwarding unconfirmed single-source findings to the LLM for re-examination (rather than trusting either analyzer at face value), lifts precision by **+23.5 percentage points** over ungrounded zero-shot prompting on this benchmark — while *also* improving recall, since the AST pass independently catches patterns (hardcoded secrets outside Bandit's `password`-only naming heuristic, quadratic membership checks, string concatenation in loops) that neither Bandit nor a keyword-matching zero-shot pass covers on its own.

Re-run it yourself: `bash scripts/evaluate.sh` (regenerates the dataset, then the report — fully deterministic, ~2s on the mock LLM client).

**Known limitations**, kept visible rather than tuned away in the benchmark: the weak-crypto rule flags any `hashlib.md5`/`sha1` call regardless of whether it's used for a security purpose or just a checksum (the one remaining false positive above — a real limitation Bandit's own `B303`/`B324` rules share); and the AST shell-injection check pattern-matches `subprocess.run(...)`/`.run(...)` call sites specifically, so a `subprocess.Popen(cmd, shell=True)` variant is only caught because Bandit's own `B602` rule happens to cover `Popen` too — if Bandit were disabled, that pattern would slip through the AST-only path.

---

## 🏗️ Architecture & Graph Flow

```
                         ┌───────────────┐
                         │   parse_diff   │  unified diff → per-file,
                         │                │  per-hunk structured data
                         └───────┬───────┘
                                 ▼
                         ┌───────────────┐
                         │  static_scan   │  Bandit (real) + custom AST
                         │                │  checks, cross-validated
                         └───────┬───────┘
                                 ▼
                         ┌───────────────┐
                    ┌────│ route (cond.)  │────┐
                    │    └───────────────┘    │
          no findings                   findings present
                    │                          │
                    ▼                          ▼
            ┌───────────────┐        ┌────────────────────┐
            │   quick_pass   │        │  deep_llm_review     │
            │ (skip the LLM) │        │  verified  → auto-   │
            └───────┬───────┘        │    confirm, high conf│
                    │                 │  unverified → LLM    │
                    │                 │    re-examines before │
                    │                 │    confirm/dismiss    │
                    │                 └──────────┬───────────┘
                    └───────────────┬─────────────┘
                                     ▼
                         ┌─────────────────────┐
                         │ aggregate_feedback    │  severity-sorted
                         │                       │  PR comments + summary
                         └─────────────────────┘
```

| Node | File | What it does |
| :--- | :--- | :--- |
| `parse_diff` | `src/diff_utils.py`, `src/graph/nodes.py` | Parses unified diff text into `FileDiff`/`Hunk` objects; filters to changed Python files. |
| `static_scan` | `src/analysis/bandit_runner.py`, `src/analysis/ast_checks.py`, `src/analysis/cross_validate.py` | Runs real Bandit against materialized added-line snippets; runs 10 custom AST checks (6 security, 2 performance, plus SQL-injection variable tracking and set-vs-list membership tracking); cross-validates overlapping rule families by file+line to mark findings `verified`. |
| `route_after_static_scan` | `src/graph/nodes.py` | Conditional edge: `quick_pass` if no findings, else `deep_llm_review`. |
| `deep_llm_review` | `src/graph/nodes.py`, `src/llm/*` | Per finding: verified findings are confirmed with full context; unverified findings are re-examined by the LLM client (dismissed as false positives if they don't hold up) before being surfaced. |
| `aggregate_feedback` | `src/feedback.py` | Formats confirmed findings into severity-sorted, PR-comment-shaped output with a one-line summary. |

---

## 🧰 Project Layout

```
src/
  diff_utils.py        # unified diff → structured FileDiff/Hunk objects
  feedback.py           # findings → PR-comment-shaped output
  cli.py                 # `python -m src.cli` entrypoint
  analysis/
    bandit_runner.py    # real Bandit, invoked as a subprocess, JSON parsed
    ast_checks.py        # 10 custom AST checks (security + performance)
    cross_validate.py    # couples Bandit + AST findings, marks `verified`
  llm/
    base.py              # LLMClient interface (review_snippet, zero_shot_scan)
    qwen_client.py        # real Qwen2.5-Coder client (OpenAI-compatible endpoint)
    mock_client.py         # deterministic offline stand-in (default)
    factory.py              # builds the configured client from agent.yaml
  graph/
    state.py              # ReviewState TypedDict, Finding schema
    nodes.py                # node implementations + routing logic
    build_graph.py           # wires nodes into a compiled LangGraph StateGraph
eval/
  seed_vulnerabilities.py  # generates the benchmark dataset
  run_benchmark.py          # baseline vs. pipeline precision/recall/FPR
data/
  benchmark/seeded_vulnerabilities.jsonl  # generated benchmark (regenerable)
  examples/sample_pr.diff                   # bundled demo diff
configs/agent.yaml      # LLM provider, routing thresholds, output settings
tests/                    # pytest suite (diff parsing, AST checks, cross-
                            # validation, graph routing, benchmark scoring)
```

---

## 🚀 Getting Started

```bash
pip install -r requirements.txt

# Review a bundled example diff (no setup required — uses the mock LLM client)
bash scripts/run_demo.sh

# Review any diff
python -m src.cli --diff path/to/change.diff
git diff main... | python -m src.cli --stdin
python -m src.cli --repo . --against main --json   # raw findings as JSON

# Run the test suite
pytest

# Reproduce the benchmark numbers above
bash scripts/evaluate.sh
```

### Using a real Qwen2.5-Coder model

Everything above runs against `MockQwenClient` by default (see `src/llm/mock_client.py` for why that's a meaningful stand-in, not a stub). To use a real model, serve Qwen2.5-Coder behind any OpenAI-compatible endpoint and switch the provider:

```bash
# e.g. via Ollama
ollama run qwen2.5-coder:7b
```

```yaml
# configs/agent.yaml
llm:
  provider: qwen
  base_url: http://localhost:11434/v1
  model: Qwen/Qwen2.5-Coder-7B-Instruct
```

Nothing else changes — `src/llm/factory.py` builds whichever client the config names, and both implement the same `LLMClient` interface (`src/llm/base.py`).

---

## Why this architecture

The precision gain isn't from asking the LLM to "be careful" — it's structural:

1. **Two independent analyzers, not one.** Bandit's rules are substantially textual/pattern-based (its own `B608` SQL-injection check, for instance, is a known source of false positives). The AST pass re-derives the same signal from the parse tree. Agreement between the two is a much stronger precision signal than either alone.
2. **The LLM's job is narrow and falsifiable.** It isn't asked to find issues from scratch (that's the naive zero-shot baseline, measured separately) — it's asked to confirm or dismiss a specific, already-localized candidate finding, with the surrounding code as context. That's a much easier, more reliable task, and it's where "contextual PR feedback" (an exploit explanation, a concrete fix) comes from.
3. **Routing bounds the cost.** `quick_pass` means clean diffs never reach the LLM at all; `max_llm_findings_per_file` bounds worst-case spend on a single large diff.

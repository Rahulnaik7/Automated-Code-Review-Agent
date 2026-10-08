# 🤖 Qwen2.5-Coder-Security-Reviewer

[![Agent Framework](https://img.shields.io/badge/Orchestration-LangGraph-blue)](#)
[![Model](https://img.shields.io/badge/LLM-Qwen2.5--Coder-purple)](https://huggingface.co/Qwen)
[![Static Analysis](https://img.shields.io/badge/Tools-Bandit%20%7C%20Python%20AST-orange)](#)
[![Precision](https://img.shields.io/badge/Precision-0.67%20(%2B0.09)-brightgreen)](#)

An autonomous AI code review agent powered by **Qwen2.5-Coder** and **LangGraph**. The system dynamically routes `git diffs` through a stateful analysis graph combining LLM reasoning with deterministic static analysis (Bandit + AST parsing) to catch security vulnerabilities and performance bottlenecks before PR merge.

---

## ✨ Key Capabilities

* **Stateful Flow via LangGraph:** Manages review workflows through an explicit State Graph, enabling conditional branching, retries, and modular node executions.
* **Hybrid Analysis Engine:** Pairs LLM code comprehension with rigid static analysis (Bandit AST parsing) to minimize false positives and enforce security constraints.
* **Dynamic Conditional Routing:** Routes code diffs based on vulnerability severity, code complexity, or failing static check signals.
* **Contextual PR Automation:** Generates actionable, inline-ready pull request feedback with suggested code fixes rather than generic warnings.

---

## 📊 Benchmark Results

Evaluated on a benchmark dataset seeded with real-world security vulnerabilities (OWASP Top 10, memory leaks, performance bottlenecks):

| Pipeline Configuration | Detection Precision | False Positive Rate |
| :--- | :---: | :---: |
| **Naive LLM Zero-Shot Prompting** | **0.58** | High (Hallucinated warnings) |
| **Qwen2.5-Coder + LangGraph Engine (Ours)** | **0.67 (+0.09)** | **Low (Verified by AST/Bandit)** |

> **Key Takeaway:** Combining LLM review nodes with deterministic static analysis tools cut out noisy feedback and elevated precision by **+9 percentage points**.

---

## 🏗️ Architecture & Graph Flow

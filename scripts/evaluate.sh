#!/usr/bin/env bash
# Regenerates the seeded-vulnerability benchmark and runs the baseline vs.
# pipeline comparison, writing outputs/benchmark_report.{json,md}.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m eval.seed_vulnerabilities
python3 -m eval.run_benchmark

#!/usr/bin/env bash
# Runs the agent against a bundled example diff with an obvious seeded
# issue, so you can see PR-ready output without wiring up a real repo.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m src.cli --diff data/examples/sample_pr.diff --title "Add CSV export + backup helper"

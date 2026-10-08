"""Deterministic demo runner.

Reads data/processed/sample.jsonl, produces deterministic predictions (with controlled errors),
evaluates with evaluate_batch, writes outputs/results.json and prints a short summary.
"""
import json
import sys
from pathlib import Path
from datetime import datetime

# Ensure repo root is on sys.path when run from anywhere
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.data_pipeline import load_jsonl, save_results
from src.reward import evaluate_batch


def deterministic_prediction(example, idx):
    """Predict the tool; inject controlled errors for some indices."""
    tool = example.get("tool")
    # Inject an error every 4th example by returning a wrong tool
    if idx % 4 == 0:
        # pick a deterministic wrong tool
        return {"predicted_tool": tool + "_wrong"}
    return {"predicted_tool": tool}


def main():
    data_path = ROOT / "data" / "processed" / "sample.jsonl"
    examples = load_jsonl(str(data_path))
    if not examples:
        print("No examples found at", data_path)
        return 1

    predictions = []
    for i, ex in enumerate(examples):
        pred = deterministic_prediction(ex, i)
        predictions.append({"id": ex.get("id"), **pred})

    metrics = evaluate_batch(examples, predictions)

    results = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "metrics": metrics,
        "predictions": predictions,
    }

    out_path = ROOT / "outputs" / "results.json"
    save_results(str(out_path), results)

    print("Demo finished. Summary:")
    print(json.dumps(metrics, indent=2))
    print(f"Wrote results to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

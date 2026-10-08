"""Produce a human-readable report from outputs/results.json."""
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    results_path = root / "outputs" / "results.json"
    if not results_path.exists():
        print("results.json not found. Run the demo first.")
        return 1
    results = json.loads(results_path.read_text(encoding="utf-8"))
    metrics = results.get("metrics", {})
    report_lines = ["# Demo Evaluation Report", "", "## Metrics", ""]
    for k in ["total", "correct", "accuracy"]:
        report_lines.append(f"- **{k}**: {metrics.get(k)}")

    report_lines.append("")
    report_lines.append("## Per-example details (first 20)")
    report_lines.append("")
    for item in metrics.get("details", [])[:20]:
        report_lines.append(f"- id={item.get('id')}: gt={item.get('gt')} pred={item.get('pred')} correct={item.get('correct')}")

    out = root / "outputs" / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(report_lines), encoding="utf-8")
    print(f"Wrote report to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

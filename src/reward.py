from typing import List, Dict


def evaluate_batch(examples: List[Dict], predictions: List[Dict]) -> Dict:
    """Simple deterministic evaluator comparing predicted tool name against ground truth.

    Returns accuracy and basic counts.
    """
    assert len(examples) == len(predictions)
    total = len(examples)
    correct = 0
    per_example = []
    for ex, pred in zip(examples, predictions):
        gt = ex.get("tool")
        p = pred.get("predicted_tool")
        ok = (gt == p)
        per_example.append({"id": ex.get("id"), "gt": gt, "pred": p, "correct": ok})
        if ok:
            correct += 1

    accuracy = correct / total if total > 0 else 0.0
    return {"total": total, "correct": correct, "accuracy": round(accuracy, 4), "details": per_example}

from eval.run_benchmark import ConfusionMatrix
from eval.seed_vulnerabilities import build_dataset


def test_confusion_matrix_precision_recall():
    cm = ConfusionMatrix()
    cm.record("a", predicted=True, actual=True)   # TP
    cm.record("b", predicted=True, actual=True)   # TP
    cm.record("c", predicted=True, actual=False)  # FP
    cm.record("d", predicted=False, actual=True)  # FN
    cm.record("e", predicted=False, actual=False)  # TN

    assert cm.tp == 2 and cm.fp == 1 and cm.fn == 1 and cm.tn == 1
    assert cm.precision == round(2 / 3, 4)
    assert cm.recall == round(2 / 3, 4)
    assert cm.false_positive_rate == 0.5
    assert cm.false_positive_examples == ["c"]
    assert cm.false_negative_examples == ["d"]


def test_confusion_matrix_handles_no_positive_predictions():
    cm = ConfusionMatrix()
    cm.record("a", predicted=False, actual=True)
    cm.record("b", predicted=False, actual=False)
    assert cm.precision == 0.0  # no predicted positives -> precision defined as 0, not NaN


def test_seeded_dataset_has_balanced_labeled_examples():
    examples = build_dataset()
    assert len(examples) >= 40
    ids = [e["id"] for e in examples]
    assert len(ids) == len(set(ids)), "example ids must be unique"
    vuln = [e for e in examples if e["has_issue"]]
    clean = [e for e in examples if not e["has_issue"]]
    assert len(vuln) >= 15
    assert len(clean) >= 15


def test_every_seeded_example_has_required_fields():
    examples = build_dataset()
    for e in examples:
        assert set(e.keys()) >= {"id", "file", "diff_text", "has_issue", "category", "severity"}
        assert e["diff_text"].startswith("diff --git")

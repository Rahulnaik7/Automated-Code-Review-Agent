import json
from pathlib import Path
from typing import List, Dict


def load_jsonl(path: str) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def save_results(path: str, results: Dict):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

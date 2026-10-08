import argparse
import yaml
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"Config not found: {cfg_path}")
        return 1
    cfg = yaml.safe_load(cfg_path.read_text())
    print("Loaded config:")
    for k, v in cfg.items():
        print(f"  {k}: {v}")
    print("(Training is a placeholder in this demo.)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

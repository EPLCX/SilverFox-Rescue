#!/usr/bin/env python3
"""Evaluate exported JSONL results without ever executing samples."""
import argparse, json
from pathlib import Path


def load(path: Path) -> dict[str, str]:
    result = {}
    for line in path.read_text("utf-8").splitlines():
        if line.strip():
            row = json.loads(line); result[row["sha256"].lower()] = row["verdict"]
    return result


def main() -> None:
    p = argparse.ArgumentParser(); p.add_argument("--malware", type=Path, required=True); p.add_argument("--benign", type=Path, required=True); args = p.parse_args()
    malware, benign = load(args.malware), load(args.benign)
    detected = sum(v in {"malicious", "suspicious"} for v in malware.values())
    false_positive = sum(v in {"malicious", "suspicious"} for v in benign.values())
    report = {"malware_samples": len(malware), "benign_samples": len(benign), "detection_rate": detected / len(malware) if malware else None, "false_positive_rate": false_positive / len(benign) if benign else None, "detection_target_met": bool(malware) and detected / len(malware) >= .5, "false_positive_target_met": bool(benign) and false_positive / len(benign) <= .15}
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__": main()


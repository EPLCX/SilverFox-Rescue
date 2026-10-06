#!/usr/bin/env python3
"""Recalculate verdict thresholds from saved development predictions without refitting trees."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

if __package__:
    from .tool_paths import MODEL_HEADER, MODEL_REPORT
else:
    from tool_paths import MODEL_HEADER, MODEL_REPORT

import numpy as np

if __package__:
    from .train_lightgbm import point, threshold_for
else:
    from train_lightgbm import point, threshold_for


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=MODEL_REPORT)
    parser.add_argument("--header", type=Path, default=MODEL_HEADER)
    parser.add_argument("--max-fpr", type=float, default=0.0035)
    args = parser.parse_args()
    if not 0 <= args.max_fpr <= 0.01:
        raise ValueError("max-fpr must be between 0 and 0.01")
    report = json.loads(args.report.read_text(encoding="utf-8"))
    header = args.header.read_text(encoding="utf-8")
    if f'TRAINED_AT_UTC = "{report["trained_at_utc"]}"' not in header:
        raise RuntimeError("header and evaluation report refer to different models")
    dev = [row for row in report["out_of_fold_samples"] if row["split"] == "development"]
    hold = [row for row in report["out_of_fold_samples"] if row["split"] == "holdout"]
    if not dev and "outer_cv" in report:
        dev = report["out_of_fold_samples"]
    dev_y = np.asarray([row["label"] for row in dev], dtype=np.int32)
    dev_p = np.asarray([row.get("final_calibration_oof_probability", row["probability"]) for row in dev], dtype=np.float64)
    hold_y = np.asarray([row["label"] for row in hold], dtype=np.int32)
    hold_p = np.asarray([row["probability"] for row in hold], dtype=np.float64)
    suspicious = report["development_suspicious_operating_point"]["threshold"]
    floor = max(suspicious, 0.9)
    malicious = threshold_for(dev_y, dev_p, args.max_fpr, floor)
    if malicious <= suspicious:
        raise RuntimeError("malicious threshold must be above suspicious threshold")
    changed, count = re.subn(r"(MALICIOUS_THRESHOLD = )[^;]+;",
                             lambda match: f"{match.group(1)}{malicious:.17g};", header)
    if count != 1:
        raise RuntimeError("expected one generated malicious threshold")
    report["development_malicious_operating_point"] = point(dev_y, dev_p, malicious)
    if hold:
        report["holdout_malicious_operating_point"] = point(hold_y, hold_p, malicious)
        report["holdout_malicious_note"] = "Exploratory evaluation of the selected threshold on saved holdout predictions."
    report["malicious_threshold_policy"] = {"development_max_false_positive_rate": args.max_fpr,
                                           "floor": floor}
    report["evaluation"] += "; malicious tier retuned post-hoc on development predictions"
    args.header.write_text(changed, encoding="utf-8", newline="\n")
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"development": report["development_malicious_operating_point"],
                      "holdout_exploratory": report.get("holdout_malicious_operating_point")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

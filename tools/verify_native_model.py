#!/usr/bin/env python3
"""Integration-check the compiled native engine on files from the training corpus.

The samples are opened for static reading only and are never launched.
"""

from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path

if __package__:
    from .tool_paths import ENGINE_DLL, MODEL_DIR, MODEL_REPORT
else:
    from tool_paths import ENGINE_DLL, MODEL_DIR, MODEL_REPORT

if __package__:
    from .train_static_ml import READ_LIMIT, sibling_names
else:
    from train_static_ml import READ_LIMIT, sibling_names


class FileInput(ctypes.Structure):
    _fields_ = [
        ("abi", ctypes.c_uint32),
        ("path", ctypes.c_char_p),
        ("sample", ctypes.POINTER(ctypes.c_uint8)),
        ("sample_len", ctypes.c_size_t),
        ("total_len", ctypes.c_uint64),
        ("signature_state", ctypes.c_uint32),
        ("embedded_certificate", ctypes.c_uint8),
        ("siblings", ctypes.POINTER(ctypes.c_char_p)),
        ("sibling_count", ctypes.c_size_t),
        ("gpu_prefilter_hits", ctypes.c_uint64),
        ("gpu_prefilter_valid", ctypes.c_uint64),
        ("gpu_ml_histogram", ctypes.POINTER(ctypes.c_uint32)),
        ("gpu_ml_histogram_len", ctypes.c_size_t),
    ]


class Result(ctypes.Structure):
    _fields_ = [
        ("verdict", ctypes.c_uint32),
        ("score", ctypes.c_uint16),
        ("evidence_count", ctypes.c_uint16),
        ("evidence", (ctypes.c_char * 768) * 32),
    ]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, default=ENGINE_DLL)
    parser.add_argument("--training-report", type=Path, default=MODEL_REPORT)
    parser.add_argument("--output", type=Path, default=MODEL_DIR / "native_ml_verification.json")
    parser.add_argument("--max-safe", type=int, default=300)
    parser.add_argument("--max-malicious", type=int, default=300)
    args = parser.parse_args()
    engine = ctypes.CDLL(str(args.engine.resolve()))
    scan = engine.sf_scan_file
    scan.argtypes = [ctypes.POINTER(FileInput), ctypes.POINTER(Result)]
    scan.restype = ctypes.c_int
    report = json.loads(args.training_report.read_text(encoding="utf-8"))
    rows = []
    selected = []
    safe_count = malicious_count = 0
    for expected in report["out_of_fold_samples"]:
        if expected["label"] == 0:
            if safe_count >= args.max_safe: continue
            safe_count += 1
        else:
            if malicious_count >= args.max_malicious and not expected.get("family", "").startswith("virus/"): continue
            malicious_count += 1
        selected.append(expected)
    for expected in selected:
        path = Path(expected["path"])
        size = path.stat().st_size
        with path.open("rb") as handle:
            data = handle.read(READ_LIMIT)
        ctypes.pythonapi.PyBytes_AsString.argtypes = [ctypes.py_object]
        ctypes.pythonapi.PyBytes_AsString.restype = ctypes.POINTER(ctypes.c_uint8)
        buffer = ctypes.pythonapi.PyBytes_AsString(data)
        peers = sibling_names(path, Path(report["dataset"]) / expected["family"].split("/", 1)[0])
        encoded = [name.encode("utf-8") for name in peers]
        peer_array = (ctypes.c_char_p * len(encoded))(*encoded)
        request = FileInput(
            3,
            str(path).encode("utf-8"),
            buffer,
            len(data),
            size,
            0,
            0,
            peer_array,
            len(encoded),
            0,
            0,
            None,
            0,
        )
        result = Result()
        if scan(ctypes.byref(request), ctypes.byref(result)) != 1:
            raise RuntimeError(f"native scan failed: {path}")
        evidence = [bytes(result.evidence[index]).split(b"\0", 1)[0].decode("utf-8") for index in range(result.evidence_count)]
        rows.append(
            {
                "path": str(path),
                "label": expected["label"],
                "family": expected["family"],
                "out_of_fold_probability": expected["probability"],
                "verdict": int(result.verdict),
                "score": int(result.score),
                "evidence": evidence,
            }
        )
    safe = [row for row in rows if row["label"] == 0]
    malicious = [row for row in rows if row["label"] == 1]
    false_positives = [row for row in safe if row["verdict"] != 0]
    detected = [row for row in malicious if row["verdict"] != 0]
    native = {
        "engine": str(args.engine.resolve()),
        "trained_at_utc": report["trained_at_utc"],
        "integration_count": len(rows),
        "evaluation_note": "These files were used in the final all-sample fit; this is an integration check, not an independent accuracy estimate.",
        "safe_count": len(safe),
        "malicious_count": len(malicious),
        "detected_count": len(detected),
        "named_family_match_count": sum(
            row["verdict"] in (1, 2) and
            any(text.startswith("Trojan." + row["family"].split("/", 1)[1] + suffix)
                for suffix in (".", "：")
                for text in row["evidence"])
            for row in malicious if row["family"].startswith("virus/")
        ),
        "detection_rate": len(detected) / len(malicious),
        "false_positive_count": len(false_positives),
        "false_positive_rate": len(false_positives) / len(safe),
        "ml_evidence_count": sum(any("机器学习模型" in text or "LightGBM" in text for text in row["evidence"]) for row in rows),
        "false_positives": false_positives,
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(native, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in native.items() if key not in {"rows", "false_positives"}}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

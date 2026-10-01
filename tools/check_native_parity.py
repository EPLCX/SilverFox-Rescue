#!/usr/bin/env python3
"""Compare generated LightGBM tree inference in Python and the native DLL."""
import argparse
import ctypes
import json
import math
import re
from pathlib import Path

if __package__:
    from .tool_paths import ENGINE_DLL, MODEL_HEADER, MODEL_REPORT
else:
    from tool_paths import ENGINE_DLL, MODEL_HEADER, MODEL_REPORT

if __package__:
    from .train_static_ml import READ_LIMIT, extract_features, metadata_function, sibling_names
else:
    from train_static_ml import READ_LIMIT, extract_features, metadata_function, sibling_names


def array(header, name, integer=False):
    match = re.search(rf"\b{name} = \{{(.*?)\}};", header, re.S)
    if not match: raise RuntimeError(f"missing {name}")
    values = re.findall(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?", match.group(1))
    return [int(v) if integer else float(v) for v in values]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--header", type=Path, default=MODEL_HEADER)
    parser.add_argument("--engine", type=Path, default=ENGINE_DLL)
    parser.add_argument("--report", type=Path, default=MODEL_REPORT)
    args = parser.parse_args()
    header = args.header.read_text(encoding="utf-8")
    offsets = array(header, "TREE_OFFSETS", True)
    left = array(header, "LEFT", True)
    right = array(header, "RIGHT", True)
    feature = array(header, "FEATURES", True)
    threshold = array(header, "THRESHOLDS")
    leaves = array(header, "LEAF_VALUES")
    class_count = int(re.search(r"CLASS_COUNT = (\d+);", header).group(1))
    slope = float(re.search(r"CALIBRATION_SLOPE = ([^;]+);", header).group(1))
    intercept = float(re.search(r"CALIBRATION_INTERCEPT = ([^;]+);", header).group(1))
    dll = ctypes.CDLL(str(args.engine.resolve()))
    metadata_function(args.engine)
    native = dll.sf_ml_probability_context
    native.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint64,
                       ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t]
    native.restype = ctypes.c_double
    report = json.loads(args.report.read_text(encoding="utf-8"))
    rows = report["out_of_fold_samples"]
    selected = rows[::max(1, len(rows)//20)][:20]
    large = next((row for row in rows if Path(row["path"]).stat().st_size > 16 * 1024 * 1024), None)
    if large is not None and large not in selected:
        selected.append(large)
    errors = []
    for row in selected:
        path = Path(row["path"])
        with path.open("rb") as handle: data = handle.read(READ_LIMIT)
        root = Path(report["dataset"]) / row["family"].split("/", 1)[0]
        peers = sibling_names(path, root)
        x = extract_features(data, path.stat().st_size, path, peers)
        margins = [0.0] * class_count
        for tree, base in enumerate(offsets):
            node = 0
            while feature[base+node] >= 0:
                at = base+node
                node = left[at] if x[feature[at]] <= threshold[at] else right[at]
            margins[tree % class_count] += leaves[base+node]
        largest = max(margins)
        exp_values = [math.exp(value-largest) for value in margins]
        raw = min(1-1e-7, max(1e-7, 1-exp_values[0]/sum(exp_values)))
        logit = slope*math.log(raw/(1-raw))+intercept
        expected = 1/(1+math.exp(-max(-40.0,min(40.0,logit))))
        ctypes.pythonapi.PyBytes_AsString.argtypes = [ctypes.py_object]
        ctypes.pythonapi.PyBytes_AsString.restype = ctypes.POINTER(ctypes.c_uint8)
        buffer = ctypes.pythonapi.PyBytes_AsString(data)
        encoded = [name.encode("utf-8") for name in peers]
        peer_array = (ctypes.c_char_p * len(encoded))(*encoded)
        actual = native(buffer, len(data), path.stat().st_size,
                        str(path).encode("utf-8"), peer_array, len(encoded))
        errors.append({"path": str(path), "expected": expected, "actual": actual,
                       "absolute_error": abs(expected-actual)})
    worst = max(errors, key=lambda row: row["absolute_error"])
    print(json.dumps({"checked": len(errors), "worst": worst}, ensure_ascii=False, indent=2))
    if worst["absolute_error"] > 1e-6:
        raise SystemExit("native model differs from generated-tree reference")


if __name__ == "__main__": main()

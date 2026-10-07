#!/usr/bin/env python3
"""Train one native LightGBM model for Safe, Generic, and virus families."""
from __future__ import annotations

import argparse
import json
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from .tool_paths import ENGINE_DLL, ROOT, MODEL_DIR, MODEL_HEADER, MODEL_REPORT, prepare_temp_dir
    from . import train_static_ml as static_ml
else:
    from tool_paths import ENGINE_DLL, ROOT, MODEL_DIR, MODEL_HEADER, MODEL_REPORT, prepare_temp_dir
    import train_static_ml as static_ml

prepare_temp_dir()

import lightgbm as lgb
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

if __package__:
    from .train_static_ml import FEATURE_NAMES, c_float, load_extra_safe, load_samples, remove_conflicting_duplicates
else:
    from train_static_ml import FEATURE_NAMES, c_float, load_extra_safe, load_samples, remove_conflicting_duplicates


CONFIGS = {
    "specified": dict(n_estimators=1000, learning_rate=0.03, num_leaves=23, max_depth=-1,
                       min_child_samples=15, subsample=1.0, subsample_freq=1,
                       colsample_bytree=0.7, reg_lambda=6.0, min_split_gain=0.0,
                       random_state=42, n_jobs=-1, deterministic=True, force_row_wise=True),
}


def model(config: dict):
    return lgb.LGBMClassifier(**config, objective="multiclass", verbosity=-1)


def report_iteration(env):
    if (env.iteration + 1) % 500 == 0:
        print(f"iteration {env.iteration + 1}/{env.end_iteration}", flush=True)


def probabilities(fitted, x, class_count):
    values = np.zeros((len(x), class_count), np.float64)
    predicted = fitted.predict_proba(x)
    for column, label in enumerate(fitted.classes_):
        values[:, int(label)] = predicted[:, column]
    return values


def grouped_oof(x, y, weights, config, class_count, splits):
    values = np.zeros((len(y), class_count), np.float64)
    for fold, (train, valid) in enumerate(splits, 1):
        fitted = model(config)
        fitted.fit(x[train], y[train], sample_weight=weights[train], callbacks=[report_iteration])
        values[valid] = probabilities(fitted, x[valid], class_count)
        print(f"fold {fold}/5: {len(valid)} validated", flush=True)
    return values


SAFE_STRATA = ("UPX加壳", "VMProtect相关", "易语言", "NET单文件程序", "驱动",
               "安装器或卸载器", "NET托管程序", "大型高熵数据节", "含RWX节", "大型非证书尾部")


def load_safe_catalog(path):
    if not path.is_file():
        print(f"safe classification: {path} absent; classify loaded safe bytes", flush=True)
        return {}
    rows = json.loads(path.read_text(encoding="utf-8"))["samples"]
    return {str(Path(row["path"]).resolve()).casefold(): row for row in rows}


def stratification_labels(samples, y, groups, class_count):
    # Keep the model's Safe class, while distributing its structural cohorts across folds.
    primary = [next((name for name in SAFE_STRATA if name in s.safe_categories), "其他白样本")
               if s.label == 0 else "" for s in samples]
    strata = y.copy()
    retained = {}
    for name in SAFE_STRATA:
        indices = np.asarray([i for i, category in enumerate(primary) if category == name], dtype=np.int64)
        group_count = len(np.unique(groups[indices]))
        if group_count >= 5:
            strata[indices] = class_count + len(retained)
            retained[name] = {"samples": len(indices), "groups": group_count}
    return strata, retained


def safe_category_metrics(samples, groups, probability, suspicious, malicious):
    categories = sorted({category for sample in samples if sample.label == 0 for category in sample.safe_categories})
    result = {}
    for category in categories:
        indices = np.asarray([i for i, s in enumerate(samples) if s.label == 0 and category in s.safe_categories], dtype=np.int64)
        p = probability[indices]
        result[category] = {"sample_count": len(indices), "group_count": len(np.unique(groups[indices])),
                            "suspicious_or_malicious_count": int((p >= suspicious).sum()),
                            "malicious_count": int((p >= malicious).sum()),
                            "false_positive_rate": float((p >= suspicious).mean()),
                            "malicious_false_positive_rate": float((p >= malicious).mean())}
    return result


def point(y, p, threshold):
    tn, fp, fn, tp = confusion_matrix(y, p >= threshold, labels=[0, 1]).ravel()
    return {"threshold": float(threshold), "safe": int(tn+fp), "malicious": int(tp+fn),
            "false_positive": int(fp), "true_positive": int(tp),
            "false_positive_rate": float(fp/max(tn+fp, 1)), "recall": float(tp/max(tp+fn, 1)),
            "precision": float(tp/max(tp+fp, 1))}


def threshold_for(y, p, max_fpr, floor):
    allowance = int((y == 0).sum() * max_fpr)
    candidates = np.unique(p[p >= floor])
    for threshold in candidates:
        if np.count_nonzero((y == 0) & (p >= threshold)) <= allowance:
            return float(threshold)
    return 1.0


def calibrate(probabilities, slope, intercept):
    raw = np.clip(probabilities, 1e-7, 1-1e-7)
    margin = np.log(raw / (1-raw))
    values = np.clip(slope * margin + intercept, -40, 40)
    return 1 / (1 + np.exp(-values))


def flatten(booster):
    offsets, left, right, features, thresholds, values = [], [], [], [], [], []
    def visit(node):
        at = len(features)
        features.append(-1); left.append(-1); right.append(-1); thresholds.append(0.0); values.append(0.0)
        if "leaf_value" in node:
            values[at] = float(node["leaf_value"])
        else:
            assert node["decision_type"] == "<=", node["decision_type"]
            assert node["missing_type"] == "None", node["missing_type"]
            features[at] = int(node["split_feature"])
            thresholds[at] = float(node["threshold"])
            left[at] = visit(node["left_child"])
            right[at] = visit(node["right_child"])
        return at
    for info in booster.dump_model()["tree_info"]:
        offsets.append(len(features))
        visit(info["tree_structure"])
        base = offsets[-1]
        for at in range(base, len(features)):
            if features[at] >= 0:
                left[at] -= base; right[at] -= base
    return offsets, left, right, features, thresholds, values


def flat_raw(tree, x, k):
    offsets, left, right, feat, thr, val = map(np.asarray, tree)
    out = np.zeros((len(x), k), dtype=np.float64)
    rows = np.arange(len(x))
    for t, base in enumerate(offsets):
        nodes = np.full(len(x), base, dtype=np.int64)
        active = feat[nodes] >= 0
        while active.any():
            r = rows[active]
            n = nodes[active]
            nodes[active] = base + np.where(x[r, feat[n]] <= thr[n], left[n], right[n])
            active = feat[nodes] >= 0
        out[:, t % k] += val[nodes]
    return out


FPR_POINTS = (0.001, 0.0035, 0.005, 0.01)


def low_fpr(y, p):
    # nextafter excludes a tied negative score rather than exceeding the FPR budget.
    safe = np.sort(p[y == 0])[::-1]
    result = {}
    for fpr in FPR_POINTS:
        allowance = int(len(safe) * fpr)
        threshold = float(np.nextafter(safe[allowance], np.inf))
        result[str(fpr)] = point(y, p, threshold)
    return result


def bootstrap_fpr(y, p, groups, seed, iterations=500):
    unique, inverse = np.unique(groups, return_inverse=True)
    members = [np.flatnonzero(inverse == i) for i in range(len(unique))]
    rng = np.random.default_rng(seed)
    recalls = {str(fpr): [] for fpr in FPR_POINTS}
    for _ in range(iterations):
        selected = np.concatenate([members[i] for i in rng.integers(len(unique), size=len(unique))])
        if len(np.unique(y[selected])) != 2:
            continue
        for fpr, metrics in low_fpr(y[selected], p[selected]).items():
            recalls[fpr].append(metrics["recall"])
    return {fpr: {"recall_95_ci": np.quantile(values, [0.025, 0.975]).tolist(),
                  "bootstrap_iterations": len(values), "resampling_unit": "group"}
            for fpr, values in recalls.items()}


def fitted_calibration(binary, raw):
    raw = np.clip(raw, 1e-7, 1-1e-7)
    margin = np.log(raw / (1-raw)).reshape(-1, 1)
    fitted = LogisticRegression(C=1e6, max_iter=500).fit(margin, binary)
    slope, intercept = float(fitted.coef_[0, 0]), float(fitted.intercept_[0])
    if slope <= 0:
        raise RuntimeError("calibration reversed model ranking")
    p = calibrate(raw, slope, intercept)
    suspicious = threshold_for(binary, p, 0.005, 0.01)
    malicious = threshold_for(binary, p, 0.0035, max(suspicious, 0.9))
    return slope, intercept, p, suspicious, malicious


def lines(values, format_value=str, width=10):
    return ["    " + ", ".join(format_value(value) for value in values[i:i+width]) + ","
            for i in range(0, len(values), width)]


def write_header(path, tree, classes, suspicious, malicious, slope, intercept, timestamp):
    offsets, left, right, features, thresholds, values = tree
    declarations = [
        ("std::uint32_t", "TREE_OFFSETS", offsets, str),
        ("std::int32_t", "LEFT", left, str), ("std::int32_t", "RIGHT", right, str),
        ("std::int16_t", "FEATURES", features, str),
        ("double", "THRESHOLDS", thresholds, lambda v: c_float(float(v))),
        ("double", "LEAF_VALUES", values, lambda v: c_float(float(v))),
    ]
    body = ["// Generated by tools/train_lightgbm.py. Do not edit by hand.", "#pragma once",
            "#include <array>", "#include <cstddef>", "#include <cstdint>",
            "namespace silverfox_ml_model {",
            f"inline constexpr std::size_t FEATURE_COUNT = {len(FEATURE_NAMES)};",
            f"inline constexpr std::size_t CLASS_COUNT = {len(classes)};",
            f"inline constexpr std::size_t TREE_COUNT = {len(offsets)};",
            f"inline constexpr std::size_t NODE_COUNT = {len(features)};",
            "inline constexpr std::uint64_t MIN_FILE_BYTES = 2048;",
            f"inline constexpr double SUSPICIOUS_THRESHOLD = {c_float(suspicious)};",
            f"inline constexpr double MALICIOUS_THRESHOLD = {c_float(malicious)};",
            f"inline constexpr double CALIBRATION_SLOPE = {c_float(slope)};",
            f"inline constexpr double CALIBRATION_INTERCEPT = {c_float(intercept)};",
            f'inline constexpr const char *TRAINED_AT_UTC = "{timestamp}";',
            "inline constexpr std::array<const char *, CLASS_COUNT> CLASS_NAMES = {",
            *lines(classes, lambda value: f'"{value}"', 6), "};"]
    for datatype, name, data, formatter in declarations:
        body += [f"inline constexpr std::array<{datatype}, {'TREE_COUNT' if name=='TREE_OFFSETS' else 'NODE_COUNT'}> {name} = {{",
                 *lines(data, formatter, 6 if datatype == "double" else 12), "};"]
    body += ["} // namespace silverfox_ml_model", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body), encoding="utf-8", newline="\n")


def existing_calibration(path):
    header = path.read_text(encoding="utf-8")
    values = []
    for name in ("CALIBRATION_SLOPE", "CALIBRATION_INTERCEPT", "SUSPICIOUS_THRESHOLD", "MALICIOUS_THRESHOLD"):
        match = re.search(rf"\b{name} = ([^;]+);", header)
        if not match:
            raise RuntimeError(f"missing existing {name} in {path}")
        values.append(float(match.group(1)))
    if not np.isfinite(values).all() or values[0] <= 0 or not 0 <= values[2] <= values[3] <= 1:
        raise RuntimeError("invalid existing calibration or thresholds")
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=os.environ.get("SILVERFOX_DATASET_DIR"),
                        required=not bool(os.environ.get("SILVERFOX_DATASET_DIR")))
    parser.add_argument("--header", type=Path, default=MODEL_HEADER)
    parser.add_argument("--report", type=Path, default=MODEL_REPORT)
    parser.add_argument("--booster-out", type=Path, default=MODEL_DIR / "static_ml_booster.txt")
    parser.add_argument("--extra-safe", type=Path, action="append", default=[],
                        help="confirmed safe PE regression sample; may be repeated")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--evaluate", action="store_true",
                        help="run grouped 5-fold evaluation, calibration and weight ablations before final fit")
    parser.add_argument("--engine", type=Path, default=ENGINE_DLL,
                        help="DLL containing the corrected certificate/overlay extractor")
    parser.add_argument("--safe-classification", type=Path,
                        default=ROOT / "output/safe-classification-2026.10.7/samples.json",
                        help="content classification inventory; new/changed files are classified from loaded bytes")
    args = parser.parse_args()
    static_ml.ENGINE_DLL = args.engine.resolve()
    static_ml.metadata_function(static_ml.ENGINE_DLL)
    if not hasattr(static_ml._metadata_function[0], "sf_pe_overlay_info"):
        raise RuntimeError("DLL lacks corrected overlay extractor; run engine/build-engine.bat or specify --engine")
    safe_catalog = load_safe_catalog(args.safe_classification)
    samples, skipped = load_samples(args.dataset, safe_catalog)
    samples.extend(load_extra_safe(args.extra_safe, safe_catalog))
    samples, conflicts = remove_conflicting_duplicates(samples)
    if not samples:
        raise RuntimeError("no eligible PE samples")
    families = sorted({sample.family.split("/", 1)[1] for sample in samples
                       if sample.family.startswith("virus/") and sample.family != "virus/Generic"})
    if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]*", name) for name in families):
        raise RuntimeError("family directory names must be safe ASCII identifiers")
    classes = ["Safe", "Generic", *families]
    class_index = {name: index for index, name in enumerate(classes)}
    labels = ["Safe" if sample.label == 0 else
              sample.family.split("/", 1)[1] if sample.family.startswith("virus/") else "Generic"
              for sample in samples]
    x = np.stack([sample.features for sample in samples]).astype(np.float64)
    y = np.asarray([class_index[label] for label in labels], np.int32)
    binary = (y != 0).astype(np.int32)
    groups = np.asarray([sample.group for sample in samples])
    focus = np.asarray([sample.family.startswith("virus/") for sample in samples])
    counts = np.bincount(y, minlength=len(classes))
    weights = np.asarray([1.0 if label == 0 else min(12.0, max(1.0, math.sqrt(counts[1]/max(counts[label], 1))))
                          for label in y], np.float64)
    weights[focus] *= 2.0
    print(json.dumps({"sample_count": len(y), "classes": dict(zip(classes, map(int, counts))),
                      "virus_pe_samples": int(focus.sum())}, ensure_ascii=False), flush=True)
    if not np.isfinite(x).all():
        raise RuntimeError("training features contain NaN or infinity")
    safe_groups, safe_group_sizes = np.unique(groups[binary == 0], return_counts=True)
    group_audit = {"safe_samples": int((binary == 0).sum()), "safe_groups": len(safe_groups),
                   "safe_multi_sample_groups": int((safe_group_sizes > 1).sum()),
                   "safe_samples_in_multi_sample_groups": int(safe_group_sizes[safe_group_sizes > 1].sum()),
                   "largest_safe_group": int(safe_group_sizes.max()),
                   "class_group_counts": {name: len(np.unique(groups[y == i])) for i, name in enumerate(classes)}}
    print(json.dumps({"group_audit": group_audit}, ensure_ascii=False), flush=True)
    best_name, best_config = next(iter(CONFIGS.items()))
    if len(CONFIGS) != 1:
        raise RuntimeError("compare configurations using mean recall over FPR_POINTS before selecting one")
    if args.evaluate:
        outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=args.seed)
        strata, safe_strata = stratification_labels(samples, y, groups, len(classes))
        splits = list(outer.split(x, strata, groups))
        for train, valid in splits:
            if set(groups[train]) & set(groups[valid]):
                raise RuntimeError("group leaked between train and validation")
        print("outer evaluation: full grouped 5-fold OOF", flush=True)
        outer_classes = grouped_oof(x, y, weights, best_config, len(classes), splits)
        fold_ids = np.zeros(len(y), dtype=np.int32)
        fold_reports = []
        for fold, (train, valid) in enumerate(splits, 1):
            if set(groups[train]) & set(groups[valid]):
                raise RuntimeError("group leaked between train and validation")
            raw = 1-outer_classes[valid, 0]
            fold_ids[valid] = fold
            metrics = {"fold": fold, "train_count": len(train), "valid_count": len(valid),
                       "train_class_counts": dict(zip(classes, map(int, np.bincount(y[train], minlength=len(classes))))),
                       "valid_class_counts": dict(zip(classes, map(int, np.bincount(y[valid], minlength=len(classes))))),
                       "valid_safe_category_counts": {category: sum(category in samples[i].safe_categories for i in valid if binary[i] == 0)
                                                      for category in sorted({c for s in samples if s.label == 0 for c in s.safe_categories})},
                       "roc_auc": float(roc_auc_score(binary[valid], raw)),
                       "average_precision": float(average_precision_score(binary[valid], raw)),
                       "low_fpr": low_fpr(binary[valid], raw)}
            fold_reports.append(metrics)
            print(json.dumps(metrics, ensure_ascii=False), flush=True)
        full_oof_raw = 1-outer_classes[:, 0]
        slope, intercept, dev_probability, suspicious, malicious = fitted_calibration(binary, full_oof_raw)
        pooled_low_fpr = low_fpr(binary, full_oof_raw)
        intervals = bootstrap_fpr(binary, full_oof_raw, groups, args.seed)
        for fpr in pooled_low_fpr:
            pooled_low_fpr[fpr].update(intervals[fpr])
        ablations = {"original": {"pooled_low_fpr": pooled_low_fpr,
                                  "mean_fold_recall": {str(fpr): float(np.mean([v["low_fpr"][str(fpr)]["recall"] for v in fold_reports]))
                                                       for fpr in FPR_POINTS}}}
        class_weights = weights.copy()
        class_weights[focus] /= 2.0
        no_class_weights = np.ones(len(y), dtype=np.float64)
        no_class_weights[focus] *= 2.0
        for name, ablation_weights in (("without_virus_x2", class_weights), ("without_class_weights", no_class_weights)):
            scores = np.zeros(len(y), dtype=np.float64)
            fold_scores = []
            for fold, (train, valid) in enumerate(splits, 1):
                print(f"ablation {name} fold {fold}/5", flush=True)
                fitted = model(best_config)
                fitted.fit(x[train], y[train], sample_weight=ablation_weights[train], callbacks=[report_iteration])
                scores[valid] = 1-probabilities(fitted, x[valid], len(classes))[:, 0]
                fold_scores.append(low_fpr(binary[valid], scores[valid]))
                del fitted
            ablations[name] = {"pooled_low_fpr": low_fpr(binary, scores),
                               "mean_fold_recall": {str(fpr): float(np.mean([v[str(fpr)]["recall"] for v in fold_scores]))
                                                    for fpr in FPR_POINTS}}
            print(json.dumps({"ablation": name, "metrics": ablations[name]}, ensure_ascii=False), flush=True)
    else:
        slope, intercept, suspicious, malicious = existing_calibration(args.header)
        print("direct full-data fit: using existing calibration and thresholds", flush=True)
    print("final fit: all eligible samples", flush=True)
    final = model(best_config)
    final.fit(x, y, sample_weight=weights, callbacks=[report_iteration])
    tree = flatten(final.booster_)
    parity_x = x[:500].copy()
    reference = final.booster_.predict(parity_x, raw_score=True)
    parity_error = float(np.abs(flat_raw(tree, parity_x, len(classes))-reference).max())
    if not np.isfinite(parity_error) or parity_error >= 1e-6:
        raise RuntimeError(f"flattened tree raw-score mismatch: {parity_error}")
    args.booster_out.parent.mkdir(parents=True, exist_ok=True)
    final.booster_.save_model(str(args.booster_out))
    parity_path = args.report.parent / "static_ml_parity_vectors.npz"
    parity_path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(parity_path, x=parity_x, raw_score=reference,
                        paths=np.asarray([str(sample.path) for sample in samples[:500]]))
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    write_header(args.header, tree, classes, suspicious, malicious, slope, intercept, timestamp)
    report = {
        "model": "LightGBM single multiclass GBDT", "trained_at_utc": timestamp,
        "dataset": str(args.dataset), "feature_count": len(FEATURE_NAMES), "feature_names": FEATURE_NAMES,
        "extra_safe_paths": [str(path) for path in args.extra_safe],
        "class_names": classes, "class_counts": dict(zip(classes, map(int, counts))),
        "sample_count": len(y), "final_fit_count": len(y), "virus_pe_samples": int(focus.sum()),
        "tree_count": len(tree[0]), "node_count": len(tree[3]), "supported_input": "valid_pe_only",
        "evaluation": "grouped_5_fold" if args.evaluate else "not_performed",
        "selected_config": best_name, "candidate_configs": CONFIGS, "split_seed": args.seed,
        "group_audit": group_audit,
        "feature_extractor": {"engine": str(static_ml.ENGINE_DLL), "overlay": "exclude structurally validated WIN_CERTIFICATE regions"},
        "safe_classification": {"inventory": str(args.safe_classification),
                                "category_counts": {category: sum(category in sample.safe_categories for sample in samples if sample.label == 0)
                                                    for category in sorted({c for sample in samples if sample.label == 0 for c in sample.safe_categories})}},
        "calibration": {"method": "sigmoid_on_full_5_fold_oof" if args.evaluate else "retained_existing",
                        "slope": slope, "intercept": intercept},
        "thresholds": {"suspicious": suspicious, "malicious": malicious},
        "flatten_parity": {"checked": len(parity_x), "max_raw_score_error": parity_error, "vectors": str(parity_path)},
        "skipped": skipped, "conflicting_duplicate_groups_removed": conflicts,
    }
    sample_rows = [{"path": str(s.path), "label": int(s.label), "family": s.family,
                    "group": s.group, "safe_categories": list(s.safe_categories)} for s in samples]
    if args.evaluate:
        predicted_family = outer_classes[:, 1:].argmax(axis=1) + 1
        named = y > 1
        report["safe_classification"].update(safe_strata=safe_strata,
            category_metrics=safe_category_metrics(samples, groups, dev_probability, suspicious, malicious))
        report["calibration"].update(C=1e6, raw_brier=float(brier_score_loss(binary, full_oof_raw)),
                                    calibrated_brier=float(brier_score_loss(binary, dev_probability)))
        report.update(
            development_suspicious_operating_point=point(binary, dev_probability, suspicious),
            development_malicious_operating_point=point(binary, dev_probability, malicious),
            outer_cv={"folds": fold_reports, "roc_auc": float(roc_auc_score(binary, full_oof_raw)),
                      "average_precision": float(average_precision_score(binary, full_oof_raw)),
                      "virus_recall_at_fpr_0_005": float((full_oof_raw[focus] >= pooled_low_fpr["0.005"]["threshold"]).mean()),
                      "named_family_accuracy": float((predicted_family[named] == y[named]).mean()), "low_fpr": pooled_low_fpr},
            weight_ablation=ablations,
            out_of_fold_samples=[{**row, "probability": float(dev_probability[i]), "raw_probability": float(full_oof_raw[i]),
                                  "final_calibration_oof_probability": float(dev_probability[i]),
                                  "predicted_family": classes[int(predicted_family[i])], "fold": int(fold_ids[i]), "split": "outer_cv"}
                                 for i, row in enumerate(sample_rows)])
    else:
        report["calibration"]["source_header"] = str(args.header)
        report["training_samples"] = sample_rows
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("sample_count", "selected_config", "evaluation", "group_audit", "flatten_parity")},
                     ensure_ascii=False, indent=2), flush=True)



if __name__ == "__main__":
    main()

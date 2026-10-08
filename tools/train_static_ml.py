#!/usr/bin/env python3
"""Extract the same bounded PE features used by the native scan engine."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import re
import struct
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from .tool_paths import ENGINE_DLL, MODEL_HEADER, MODEL_REPORT, prepare_temp_dir
else:
    from tool_paths import ENGINE_DLL, MODEL_HEADER, MODEL_REPORT, prepare_temp_dir

prepare_temp_dir()

import numpy as np
import pefile
import lightgbm as lgb
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold

READ_LIMIT = 256 * 1024 * 1024
MAX_RUNTIME_FILE = 256 * 1024 * 1024
MIN_MODEL_FILE = 2 * 1024
METADATA_COUNT = 71
# The native extractor exposes a 71-slot ABI. Model inputs exclude network
# indicators and directory-companion counts to keep features independent of
# the surrounding file layout.
EXCLUDED_METADATA_INDICES = frozenset((23, 30, 33, 34, 35, 47, 52, *range(63, 71)))
MODEL_METADATA_INDICES = tuple(index for index in range(METADATA_COUNT)
                               if index not in EXCLUDED_METADATA_INDICES)
SCALAR_NAMES = [
    "log1p_size",
    "entropy",
    "chunk_entropy_mean",
    "chunk_entropy_std",
    "chunk_entropy_min",
    "chunk_entropy_max",
    "printable_ratio",
    "zero_ratio",
    "high_bit_ratio",
    "unique_byte_ratio",
    "mz_header",
    "valid_pe",
    "pe_section_count",
    "pe_executable_section_ratio",
    "pe_overlay_ratio",
]
PE_METADATA_NAMES = ["pe_timestamp", "pe_timestamp_invalid", "pe_machine", "pe_characteristics",
                    "pe_dll", "pe_large_address_aware", "pe_system", "pe_magic", "pe_subsystem",
                    "pe_dll_characteristics", "pe_entry_rva", "pe_image_size", "pe_checksum_present",
                    "pe_checksum_matches", "section_wx_count", "section_rwx_count", "section_writable_count",
                    "section_nonstandard_count", "section_empty_name_count", "section_empty_raw_count",
                    "section_max_raw_size", "section_high_entropy_count", "section_nonstandard_ratio",
                    "import_network_dll_count", "import_advapi_dll_count", "import_crypto_dll_count",
                    "import_function_count", "import_ordinal_count", "import_process_api_count",
                    "import_persistence_api_count", "import_network_api_count", "import_crypto_api_count",
                    "import_dll_count", "import_network_process_combo", "import_network_persistence_combo",
                    "import_crypto_network_combo", "export_function_count", "export_forwarder_count",
                    "resource_table_present", "resource_type_count", "resource_version_present",
                    "resource_manifest_present", "resource_string_table_present", "overlay_log_size",
                    "overlay_entropy", "overlay_printable_ratio", "overlay_embedded_header",
                    "suspicious_string_count", "version_company_name_present",
                    "version_product_name_present", "version_original_filename_present",
                    "version_file_description_present", "url_string_count", "path_string_count",
                    "command_string_count", "executable_path_string_count",
                    "import_descriptor_count", "export_forwarder_ratio", "checksum_mismatch",
                    "entrypoint_in_executable_section", "overlapping_raw_sections", "section_rwx_ratio",
                    "imports_per_dll", "sibling_dll_count", "sibling_exe_count",
                    "same_stem_dll", "same_stem_exe", "same_stem_dll_with_exe",
                    "sibling_data_count", "sibling_non_executable_count", "dll_and_data_companions"]
assert len(PE_METADATA_NAMES) == METADATA_COUNT
assert {PE_METADATA_NAMES[index] for index in EXCLUDED_METADATA_INDICES} == {
    "import_network_dll_count", "import_network_api_count",
    "import_network_process_combo", "import_network_persistence_combo",
    "import_crypto_network_combo", "suspicious_string_count", "url_string_count",
    "sibling_dll_count", "sibling_exe_count", "same_stem_dll", "same_stem_exe",
    "same_stem_dll_with_exe", "sibling_data_count",
    "sibling_non_executable_count", "dll_and_data_companions",
}
FEATURE_NAMES = ([f"byte_frequency_{index:03d}" for index in range(256)] + SCALAR_NAMES
                 + [PE_METADATA_NAMES[index] for index in MODEL_METADATA_INDICES])

_metadata_function = None
_overlay_function = None


def overlay_info(data: bytes, total_size: int) -> tuple[int, int, int, int]:
    """Raw end, non-certificate tail size, validated certificate offset and size."""
    global _overlay_function
    if _overlay_function is None:
        metadata_function(ENGINE_DLL)
        function = _metadata_function[0].sf_pe_overlay_info
        function.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint64,
                             ctypes.POINTER(ctypes.c_double), ctypes.c_size_t]
        function.restype = ctypes.c_int
        _overlay_function = function
    ctypes.pythonapi.PyBytes_AsString.argtypes = [ctypes.py_object]
    ctypes.pythonapi.PyBytes_AsString.restype = ctypes.POINTER(ctypes.c_uint8)
    values = (ctypes.c_double * 4)()
    if _overlay_function(ctypes.pythonapi.PyBytes_AsString(data), len(data), total_size, values, 4) != 4:
        raise ValueError("native overlay extraction failed")
    return tuple(int(v) for v in values)


def metadata_function(engine: Path):
    global _metadata_function
    if _metadata_function is None:
        dll = ctypes.CDLL(str(engine.resolve()))
        function = dll.sf_extract_pe_metadata_context
        function.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_uint64,
                             ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t,
                             ctypes.POINTER(ctypes.c_double), ctypes.c_size_t]
        function.restype = ctypes.c_int
        _metadata_function = (dll, function)
    return _metadata_function[1]


@dataclass(frozen=True)
class Sample:
    path: Path
    label: int
    family: str
    size: int
    group: str
    features: np.ndarray
    safe_categories: tuple[str, ...] = ()


def entropy_from_counts(counts: np.ndarray, length: int) -> float:
    if length == 0:
        return 0.0
    probabilities = counts[counts > 0].astype(np.float64) / float(length)
    return float(-(probabilities * np.log2(probabilities)).sum())


def pe_features(data: bytes, total_size: int) -> tuple[float, float, float, float]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return 0.0, 0.0, 0.0, 0.0
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            return 0.0, 0.0, 0.0, 0.0
        section_count, optional_size = struct.unpack_from("<H12xH", data, pe_offset + 6)
        section_table = pe_offset + 24 + optional_size
        if optional_size > len(data) - pe_offset - 24:
            return 0.0, 0.0, 0.0, 0.0
        executable = 0
        parsed_sections = 0
        for index in range(min(section_count, 64)):
            at = section_table + index * 40
            if at + 40 > len(data):
                break
            characteristics = struct.unpack_from("<I", data, at + 36)[0]
            executable += int(bool(characteristics & 0x20000000))
            parsed_sections += 1
        overlay_ratio = overlay_info(data, total_size)[1] / max(total_size, 1)
        executable_ratio = executable / parsed_sections if parsed_sections else 0.0
        return 1.0, float(parsed_sections), executable_ratio, overlay_ratio
    except (struct.error, ValueError):
        return 0.0, 0.0, 0.0, 0.0


def sibling_names(path: Path, family_root: Path | None = None) -> list[str]:
    if family_root is not None and path.parent == family_root:
        return []
    try:
        names = [entry.name for entry in path.parent.iterdir() if entry.is_file() and entry != path]
    except OSError:
        return []
    return names if len(names) <= 64 else []


def extract_features(data: bytes, total_size: int, path: Path | None = None,
                     siblings: list[str] | None = None) -> np.ndarray:
    counts = np.zeros(256, dtype=np.float64)
    chunk_entropies = []
    printable = zero = high = 0
    length = len(data)
    for start in range(0, length, 1024 * 1024):
        end = min(start + 1024 * 1024, length)
        values = np.frombuffer(data, dtype=np.uint8, count=end - start, offset=start)
        counts += np.bincount(values, minlength=256)
        printable += int(((values >= 32) & (values <= 126)).sum() + (values == 9).sum() + (values == 10).sum() + (values == 13).sum())
        zero += int((values == 0).sum())
        high += int((values >= 128).sum())
        for at in range(0, len(values), 64 * 1024):
            block = values[at:at + 64 * 1024]
            chunk_entropies.append(entropy_from_counts(np.bincount(block, minlength=256), len(block)))
    frequencies = counts / max(length, 1)
    chunk = np.asarray(chunk_entropies or [0.0], dtype=np.float64)
    valid_pe, section_count, executable_ratio, overlay_ratio = pe_features(data, total_size)
    scalars = np.asarray(
        [
            math.log1p(total_size),
            entropy_from_counts(counts, length),
            float(chunk.mean()),
            float(chunk.std()),
            float(chunk.min()),
            float(chunk.max()),
            float(printable) / max(length, 1),
            float(zero) / max(length, 1),
            float(high) / max(length, 1),
            float(np.count_nonzero(counts)) / 256.0,
            float(data.startswith(b"MZ")),
            valid_pe,
            section_count,
            executable_ratio,
            overlay_ratio,
        ],
        dtype=np.float64,
    )
    metadata = (ctypes.c_double * METADATA_COUNT)()
    if valid_pe:
        ctypes.pythonapi.PyBytes_AsString.argtypes = [ctypes.py_object]
        ctypes.pythonapi.PyBytes_AsString.restype = ctypes.POINTER(ctypes.c_uint8)
        buffer = ctypes.pythonapi.PyBytes_AsString(data)
        peers = [name.encode("utf-8") for name in (siblings or [])]
        peer_array = (ctypes.c_char_p * len(peers))(*peers)
        extracted = metadata_function(ENGINE_DLL)(
            buffer, len(data), total_size, str(path or "").encode("utf-8"), peer_array,
            len(peers), metadata, METADATA_COUNT)
        if extracted != METADATA_COUNT:
            raise RuntimeError("native PE metadata extraction failed")
    return np.concatenate((frequencies, scalars,
                           np.ctypeslib.as_array(metadata)[list(MODEL_METADATA_INDICES)].copy()))


def safe_component_group(data: bytes, path: Path) -> str:
    """Keep versions/copies of a PE component together in a flat safe corpus."""
    try:
        with pefile.PE(data=data, fast_load=True) as pe:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            for block in getattr(pe, "FileInfo", []):
                for info in block:
                    for table in getattr(info, "StringTable", []):
                        entries = {key.decode("utf-8", "replace"): value.decode("utf-8", "replace").strip().casefold()
                                   for key, value in table.entries.items()}
                        original = entries.get("OriginalFilename", "").replace("\\", "/").rsplit("/", 1)[-1]
                        if original:
                            identity = [entries.get("CompanyName", ""), entries.get("ProductName", ""), original]
                            return "safe-component:" + json.dumps(identity, ensure_ascii=False)
    except pefile.PEFormatError:
        pass
    name = re.sub(r"\s*\(\d+\)(?=\.[^.]+$)", "", path.name.casefold())
    return "safe-filename:" + name


def safe_categories(path: Path, data: bytes, catalog: dict) -> tuple[str, ...]:
    row = catalog.get(str(path.resolve()).casefold())
    if row and row.get("sha256") == hashlib.sha256(data).hexdigest():
        return tuple(row["categories"])
    if __package__:
        from .classify_safe_samples import classify
    else:
        from classify_safe_samples import classify
    return tuple(classify(path, data)["categories"])


def load_samples(dataset: Path, safe_catalog: dict | None = None, *, feature_extractor=extract_features, valid_pe_index=267) -> tuple[list[Sample], list[dict[str, object]]]:
    definitions = [("safe", 0), ("others-virus", 1), ("virus", 1)]
    samples: list[Sample] = []
    skipped: list[dict[str, object]] = []
    metadata_function(ENGINE_DLL)
    def read_one(task):
        path, root, source, label = task
        try:
            family = (f"virus/{path.relative_to(root).parts[0]}" if path.parent != root else "virus/Generic") if source == "virus" else source
            family_root = root / path.relative_to(root).parts[0] if source == "virus" and path.parent != root else root
            size = path.stat().st_size
            if size > MAX_RUNTIME_FILE:
                return None, {"path": str(path), "reason": "larger_than_runtime_limit", "size": size}
            with path.open("rb") as handle:
                data = handle.read(min(size, READ_LIMIT))
            peers = sibling_names(path, family_root)
            features = feature_extractor(data, size, path, peers)
            if features[valid_pe_index] < 0.5:
                return None, {"path": str(path), "reason": "unsupported_non_pe", "size": size}
            group = (f"bundle:{family}:{path.parent.relative_to(root)}"
                     if path.parent != family_root else f"sample:{source}:{path.relative_to(root)}")
            if source == "safe" and path.parent == root:
                group = safe_component_group(data, path)
            categories = safe_categories(path, data, safe_catalog) if label == 0 and safe_catalog is not None else ()
            return Sample(path, label, family, size, group, features, categories), None
        except (OSError, ValueError) as error:
            return None, {"path": str(path), "reason": f"read_error:{error}"}
    for family, label in definitions:
        root = dataset / family
        if not root.is_dir():
            raise FileNotFoundError(f"missing class directory: {root}")
        paths = sorted(path for path in root.rglob("*") if path.is_file())
        tasks = ((path, root, family, label) for path in paths)
        with ThreadPoolExecutor(max_workers=2) as executor:
            for position, (sample, reason) in enumerate(executor.map(read_one, tasks), 1):
                if sample is not None: samples.append(sample)
                if reason is not None: skipped.append(reason)
                if position % 100 == 0:
                    print(f"[{family}] extracted {position}/{len(paths)}", flush=True)
    return samples, skipped


def remove_conflicting_duplicates(samples: list[Sample]) -> tuple[list[Sample], list[str]]:
    labels: dict[str, set[int]] = defaultdict(set)
    for sample in samples:
        labels[sample.group].add(sample.label)
    conflicts = sorted(group for group, values in labels.items() if len(values) > 1)
    return [sample for sample in samples if sample.group not in conflicts], conflicts


def load_extra_safe(paths: list[Path], safe_catalog: dict | None = None, *, feature_extractor=extract_features, valid_pe_index=267) -> list[Sample]:
    samples = []
    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(f"extra safe regression file not found: {path}")
        size = path.stat().st_size
        if size > MAX_RUNTIME_FILE:
            raise ValueError(f"extra safe regression file exceeds runtime limit: {path}")
        with path.open("rb") as handle:
            data = handle.read(min(size, READ_LIMIT))
        features = feature_extractor(data, size, path, sibling_names(path))
        if features[valid_pe_index] < 0.5:
            raise ValueError(f"extra safe regression file is not a valid PE: {path}")
        categories = safe_categories(path, data, safe_catalog) if safe_catalog is not None else ()
        samples.append(Sample(path, 0, "safe-regression", size, f"safe-regression:{path}", features, categories))
    return samples


def select_grouped_holdout(labels: np.ndarray, groups: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray]:
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
    train, test = next(splitter.split(np.zeros(len(labels)), labels, groups))
    return train, test


def metrics_at(labels: np.ndarray, probabilities: np.ndarray, threshold: float) -> dict[str, object]:
    predicted = (probabilities >= threshold).astype(np.int32)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predicted, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(labels, predicted, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }


def choose_threshold(
    labels: np.ndarray,
    probabilities: np.ndarray,
    *,
    floor: float,
    min_precision: float = 0.0,
    max_false_positives: int | None = None,
) -> float:
    candidates = sorted(set(float(value) for value in probabilities), reverse=True)
    valid = []
    for threshold in candidates:
        result = metrics_at(labels, probabilities, threshold)
        false_positives_ok = max_false_positives is None or result["false_positive"] <= max_false_positives
        if false_positives_ok and result["precision"] >= min_precision and threshold >= floor:
            valid.append(result)
    if not valid:
        return 1.0
    best = max(valid, key=lambda item: (item["recall"], item["precision"], item["threshold"]))
    return float(best["threshold"])


def c_float(value: float) -> str:
    return f"{value:.17g}"


def array_lines(values: list[int] | np.ndarray, formatter, width: int = 10) -> list[str]:
    return ["    " + ", ".join(formatter(value) for value in values[start : start + width]) + "," for start in range(0, len(values), width)]


def flatten_forest(model: ExtraTreesClassifier) -> dict[str, list[int] | np.ndarray]:
    offsets: list[int] = []
    left: list[int] = []
    right: list[int] = []
    feature: list[int] = []
    threshold: list[float] = []
    probability: list[float] = []
    for estimator in model.estimators_:
        tree = estimator.tree_
        offsets.append(len(feature))
        left.extend(int(value) for value in tree.children_left)
        right.extend(int(value) for value in tree.children_right)
        feature.extend(int(value) for value in tree.feature)
        threshold.extend(float(value) for value in tree.threshold)
        values = tree.value[:, 0, :]
        totals = values.sum(axis=1)
        probability.extend(float(row[1] / total) if total else 0.0 for row, total in zip(values, totals))
    return {
        "offsets": offsets,
        "left": left,
        "right": right,
        "feature": feature,
        "threshold": np.asarray(threshold, dtype=np.float64),
        "probability": np.asarray(probability, dtype=np.float64),
    }


def write_header(path: Path, forest: dict[str, list[int] | np.ndarray], calibration_slope: float, calibration_intercept: float, suspicious: float, malicious: float, metadata: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    offsets = forest["offsets"]
    feature = forest["feature"]
    content = "\n".join(
        [
            "// Generated by tools/train_static_ml.py. Do not edit by hand.",
            "#pragma once",
            "#include <array>",
            "#include <cstddef>",
            "#include <cstdint>",
            "namespace silverfox_ml_model {",
            f"inline constexpr std::size_t FEATURE_COUNT = {len(FEATURE_NAMES)};",
            f"inline constexpr std::size_t TREE_COUNT = {len(offsets)};",
            f"inline constexpr std::size_t NODE_COUNT = {len(feature)};",
            f"inline constexpr std::uint64_t MIN_FILE_BYTES = {MIN_MODEL_FILE};",
            f"inline constexpr double CALIBRATION_SLOPE = {c_float(calibration_slope)};",
            f"inline constexpr double CALIBRATION_INTERCEPT = {c_float(calibration_intercept)};",
            f"inline constexpr double SUSPICIOUS_THRESHOLD = {c_float(suspicious)};",
            f"inline constexpr double MALICIOUS_THRESHOLD = {c_float(malicious)};",
            f"inline constexpr const char *MODEL_SHA256 = \"{metadata['model_sha256']}\";",
            f"inline constexpr const char *TRAINED_AT_UTC = \"{metadata['trained_at_utc']}\";",
            "inline constexpr std::array<std::uint32_t, TREE_COUNT> TREE_OFFSETS = {",
            *array_lines(offsets, lambda value: str(int(value))),
            "};", "inline constexpr std::array<std::int32_t, NODE_COUNT> LEFT = {",
            *array_lines(forest["left"], lambda value: str(int(value))),
            "};", "inline constexpr std::array<std::int32_t, NODE_COUNT> RIGHT = {",
            *array_lines(forest["right"], lambda value: str(int(value))),
            "};", "inline constexpr std::array<std::int16_t, NODE_COUNT> FEATURES = {",
            *array_lines(feature, lambda value: str(int(value))),
            "};", "inline constexpr std::array<double, NODE_COUNT> THRESHOLDS = {",
            *array_lines(forest["threshold"], lambda value: c_float(float(value)), 6),
            "};", "inline constexpr std::array<double, NODE_COUNT> PROBABILITIES = {",
            *array_lines(forest["probability"], lambda value: c_float(float(value)), 6),
            "};",
            "} // namespace silverfox_ml_model",
            "",
        ]
    )
    path.write_text(content, encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=os.environ.get("SILVERFOX_DATASET_DIR"),
                        required=not bool(os.environ.get("SILVERFOX_DATASET_DIR")))
    parser.add_argument("--header", type=Path, default=MODEL_HEADER)
    parser.add_argument("--report", type=Path, default=MODEL_REPORT)
    parser.add_argument("--extra-safe-file", type=Path, action="append", default=[])
    parser.add_argument("--seed", type=int, default=20260921)
    args = parser.parse_args()

    samples, skipped = load_samples(args.dataset)
    samples, conflicting_groups = remove_conflicting_duplicates(samples)
    extra_safe = load_extra_safe(args.extra_safe_file)
    features = np.stack([sample.features for sample in samples])
    labels = np.asarray([sample.label for sample in samples], dtype=np.int32)
    families = np.asarray([sample.family for sample in samples])
    groups = np.asarray([sample.group for sample in samples])
    train_indices, test_indices = select_grouped_holdout(labels, groups, args.seed)

    def new_model(seed: int) -> ExtraTreesClassifier:
        return ExtraTreesClassifier(
            n_estimators=400,
            max_features=0.2,
            min_samples_leaf=2,
            class_weight="balanced",
            n_jobs=-1,
            random_state=seed,
        )

    train_labels = labels[train_indices]
    train_groups = groups[train_indices]
    oof_probabilities = np.zeros(len(train_indices), dtype=np.float64)
    inner = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=args.seed + 1)
    for fold, (fit_at, validate_at) in enumerate(inner.split(features[train_indices], train_labels, train_groups)):
        candidate = new_model(args.seed + fold + 1)
        fold_features = features[train_indices][fit_at]
        fold_labels = train_labels[fit_at]
        fold_weights = np.where(families[train_indices][fit_at] == "sliverfox-virus", 4.0, 1.0)
        if extra_safe:
            fold_features = np.vstack((fold_features, np.stack([sample.features for sample in extra_safe])))
            fold_labels = np.concatenate((fold_labels, np.zeros(len(extra_safe), dtype=np.int32)))
            fold_weights = np.concatenate((fold_weights, np.ones(len(extra_safe))))
        candidate.fit(fold_features, fold_labels, sample_weight=fold_weights)
        oof_probabilities[validate_at] = candidate.predict_proba(features[train_indices][validate_at])[:, 1]
    calibrator = LogisticRegression(C=1000.0, solver="lbfgs", random_state=args.seed)
    calibrator.fit(oof_probabilities.reshape(-1, 1), train_labels)
    calibration_slope = float(calibrator.coef_[0, 0])
    calibration_intercept = float(calibrator.intercept_[0])
    calibrated_oof = calibrator.predict_proba(oof_probabilities.reshape(-1, 1))[:, 1]
    suspicious_threshold = choose_threshold(
        train_labels, calibrated_oof, floor=0.05,
        max_false_positives=max(1, int((train_labels == 0).sum() * 0.005)),
    )
    malicious_threshold = choose_threshold(
        train_labels, calibrated_oof, floor=max(0.90, suspicious_threshold), max_false_positives=0
    )
    best_model = new_model(args.seed)
    final_features = features[train_indices]
    final_labels = train_labels
    final_weights = np.where(families[train_indices] == "sliverfox-virus", 4.0, 1.0)
    if extra_safe:
        final_features = np.vstack((final_features, np.stack([sample.features for sample in extra_safe])))
        final_labels = np.concatenate((final_labels, np.zeros(len(extra_safe), dtype=np.int32)))
        final_weights = np.concatenate((final_weights, np.ones(len(extra_safe))))
    best_model.fit(final_features, final_labels, sample_weight=final_weights)
    raw_probabilities = best_model.predict_proba(features[test_indices])[:, 1]
    probabilities = calibrator.predict_proba(raw_probabilities.reshape(-1, 1))[:, 1]
    forest = flatten_forest(best_model)
    model_bytes = (
        np.asarray(forest["offsets"], dtype="<u4").tobytes()
        + np.asarray(forest["left"], dtype="<i4").tobytes()
        + np.asarray(forest["right"], dtype="<i4").tobytes()
        + np.asarray(forest["feature"], dtype="<i2").tobytes()
        + np.asarray(forest["threshold"], dtype="<f8").tobytes()
        + np.asarray(forest["probability"], dtype="<f8").tobytes()
        + struct.pack("<dddd", calibration_slope, calibration_intercept, suspicious_threshold, malicious_threshold)
    )
    model_sha256 = hashlib.sha256(model_bytes).hexdigest()
    trained_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    report = {
        "model": "calibrated_extra_trees_pe_classifier",
        "model_sha256": model_sha256,
        "trained_at_utc": trained_at,
        "dataset": str(args.dataset.resolve()),
        "read_limit_bytes": READ_LIMIT,
        "runtime_file_limit_bytes": MAX_RUNTIME_FILE,
        "minimum_model_file_bytes": MIN_MODEL_FILE,
        "seed": args.seed,
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "parameters": {"n_estimators": 400, "max_features": 0.2, "min_samples_leaf": 2, "class_weight": "balanced", "sliverfox_sample_weight": 4.0, "hashed_trigram_features": 4096},
        "tree_count": len(forest["offsets"]),
        "node_count": len(forest["feature"]),
        "calibration": {"method": "platt_logistic", "slope": calibration_slope, "intercept": calibration_intercept},
        "oof_average_precision": float(average_precision_score(train_labels, calibrated_oof)),
        "sample_count": len(samples),
        "unique_group_count": len(set(groups)),
        "class_counts": {"safe": int((labels == 0).sum()), "malicious": int((labels == 1).sum())},
        "extra_safe_training_files": [str(sample.path.resolve()) for sample in extra_safe],
        "train_count": len(train_indices),
        "test_count": len(test_indices),
        "test_class_counts": {"safe": int((labels[test_indices] == 0).sum()), "malicious": int((labels[test_indices] == 1).sum())},
        "test_roc_auc": float(roc_auc_score(labels[test_indices], probabilities)),
        "test_average_precision": float(average_precision_score(labels[test_indices], probabilities)),
        "supported_input": "valid_pe_only",
        "threshold_selection": "five-fold calibrated out-of-fold predictions on the training partition; holdout was not used",
        "oof_suspicious_operating_point": metrics_at(train_labels, calibrated_oof, suspicious_threshold),
        "oof_malicious_operating_point": metrics_at(train_labels, calibrated_oof, malicious_threshold),
        "test_at_0_5": metrics_at(labels[test_indices], probabilities, 0.5),
        "suspicious_operating_point": metrics_at(labels[test_indices], probabilities, suspicious_threshold),
        "malicious_operating_point": metrics_at(labels[test_indices], probabilities, malicious_threshold),
        "sliverfox_holdout_count": int((families[test_indices] == "sliverfox-virus").sum()),
        "sliverfox_suspicious_recall": float((probabilities[families[test_indices] == "sliverfox-virus"] >= suspicious_threshold).mean()),
        "skipped": skipped,
        "conflicting_duplicate_groups_removed": conflicting_groups,
        "test_samples": [
            {"path": str(samples[index].path), "label": int(labels[index]), "probability": float(probability), "group": groups[index]}
            for index, probability in zip(test_indices, probabilities)
        ],
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_header(args.header, forest, calibration_slope, calibration_intercept, suspicious_threshold, malicious_threshold, report)
    print(json.dumps({key: report[key] for key in ("model_sha256", "sample_count", "unique_group_count", "class_counts", "test_count", "test_roc_auc", "test_average_precision", "test_at_0_5", "suspicious_operating_point", "malicious_operating_point")}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    # The command-line training entrypoint uses the LightGBM pipeline.
    if __package__:
        from .train_lightgbm import main as lightgbm_main
    else:
        from train_lightgbm import main as lightgbm_main
    lightgbm_main()

#!/usr/bin/env python3
"""Check certificate exclusion and retention of real overlay bytes."""
import ctypes
import json
import math
import struct
from pathlib import Path

import numpy as np
from train_static_ml import entropy_from_counts, metadata_function, overlay_info, pe_features
from tool_paths import ENGINE_DLL


def check(data, expected_tail, expected_certificate):
    start, size, offset, cert_size = overlay_info(data, len(data))
    assert size == len(expected_tail) and cert_size == expected_certificate
    assert abs(pe_features(data, len(data))[3] - size / len(data)) < 1e-15
    out = (ctypes.c_double * 71)()
    pointer = ctypes.pythonapi.PyBytes_AsString(data)
    metadata_function(ENGINE_DLL)(pointer, len(data), len(data), b"", None, 0, out, 71)
    tail = expected_tail[:1048576]
    counts = np.bincount(np.frombuffer(tail, dtype=np.uint8), minlength=256)
    assert abs(out[43] - math.log1p(size)) < 1e-12
    assert abs(out[44] - entropy_from_counts(counts, len(tail))) < 1e-12
    assert abs(out[45] - sum(32 <= v <= 126 for v in tail) / max(len(tail), 1)) < 1e-12
    assert bool(out[46]) == tail.startswith((b"MZ", b"PK"))
    return {"raw_end": start, "noncertificate_bytes": size,
            "certificate_offset": offset, "certificate_bytes": cert_size}


def main():
    data = Path(r"F:\sliverfox-file\safe\dotFix.exe").read_bytes()
    start, _, cert, size = overlay_info(data, len(data))
    assert cert == start and cert + size == len(data) and size > 0
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    optional = pe + 24
    dirs = optional + (112 if struct.unpack_from("<H", data, optional)[0] == 0x20b else 96)
    results = {"certificate_only": check(data, b"", size)}
    prefix = b"MZ real payload!"
    suffix = b"PK trailing payload"
    mixed = bytearray(data[:cert] + prefix + data[cert:] + suffix)
    struct.pack_into("<I", mixed, dirs + 32, cert + len(prefix))
    results["prefix_and_suffix"] = check(bytes(mixed), prefix + suffix, size)
    invalid = bytearray(data)
    struct.pack_into("<I", invalid, dirs + 32, len(data) + 8)
    results["out_of_bounds"] = check(bytes(invalid), bytes(invalid[start:]), 0)
    invalid = bytearray(data)
    struct.pack_into("<I", invalid, cert, 7)
    results["invalid_record_length"] = check(bytes(invalid), bytes(invalid[start:]), 0)
    invalid = bytearray(data)
    invalid[cert + 8] = 0
    results["invalid_pkcs7"] = check(bytes(invalid), bytes(invalid[start:]), 0)
    results["truncated_certificate"] = check(data[:-16], data[start:-16], 0)
    for name in ["Dokan.exe", "GoogleEarthProSetup_7.3.2.5776.exe", "samplerate.dll"]:
        sample = Path(r"F:\sliverfox-file\safe") / name
        body = sample.read_bytes()
        raw, _, at, length = overlay_info(body, len(body))
        tail = body[raw:at] + body[at+length:] if length else body[raw:]
        results[name] = check(body, tail, length)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Classify the existing safe corpus by content; write a multi-label inventory."""
from __future__ import annotations

import argparse
import collections
import csv
import ctypes
import hashlib
import json
from pathlib import Path

import pefile

if __package__:
    from .train_static_ml import MAX_RUNTIME_FILE, overlay_info
else:
    from train_static_ml import MAX_RUNTIME_FILE, overlay_info

BUNDLE_MARKER = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
NSIS_MARKER = b"\xef\xbe\xad\xdeNullsoftInst"


def refine_vmprotect(row):
    reasons = []
    if any(s.casefold().startswith(".vmp") for s in row.get("sections", [])):
        reasons.append("VMProtect .vmp section")
    if any("vmprotect" in d for d in row.get("imports", [])):
        reasons.append("VMProtect SDK import")
    version = row.get("version", {})
    if "vmprotect" in version.get("CompanyName", "").casefold() and "vmprotect" in version.get("ProductName", "").casefold():
        reasons.append("version CompanyName/ProductName identify VMProtect tool")
    row["categories"] = [c for c in row["categories"] if c != "VMProtect保护"]
    row["evidence"] = [e for e in row["evidence"] if e != "VMProtect SDK import or .vmp section"]
    if reasons:
        row["categories"] = [c for c in row["categories"] if c != "其他PE"]
        row["evidence"] = [e for e in row["evidence"] if e != "no requested structural fingerprint matched"]
        if "VMProtect相关" not in row["categories"]:
            row["categories"].append("VMProtect相关")
            row["evidence"].extend(reasons)


def classify(path: Path, data: bytes | None = None) -> dict:
    size = path.stat().st_size
    row = {"path": str(path), "size": size, "categories": [], "evidence": []}
    if size > MAX_RUNTIME_FILE:
        row["categories"] = ["超出运行时大小限制"]
        return row
    if data is None:
        data = path.read_bytes()
    row["sha256"] = hashlib.sha256(data).hexdigest()
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            msi = ctypes.WinDLL("msi")
            msi.MsiOpenDatabaseW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
            msi.MsiOpenDatabaseW.restype = ctypes.c_uint
            msi.MsiCloseHandle.argtypes = [ctypes.c_uint]
            handle = ctypes.c_uint()
            if msi.MsiOpenDatabaseW(str(path), None, ctypes.byref(handle)) == 0:
                msi.MsiCloseHandle(handle)
                row["categories"] = ["安装器或卸载器", "MSI安装包"]
                row["evidence"] = ["OLE compound header + read-only MSI database validation"]
                return row
        text = data[:4096].lower()
        if any(marker in text for marker in (b"wscript.", b"on error resume next", b"createobject(")):
            row["categories"] = ["脚本（非PE）"]
            row["evidence"] = ["WScript/VBScript content fingerprint"]
            return row
        row["categories"] = ["非PE或无效PE"]
        return row
    with pe:
        pe.parse_data_directories(directories=[1, 2, 14])
        sections = [s.Name.rstrip(b"\0").decode("ascii", "replace") for s in pe.sections]
        imports = [entry.dll.decode("ascii", "replace").casefold()
                   for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        versions = {}
        for block in getattr(pe, "FileInfo", []):
            for entry in block:
                for table in getattr(entry, "StringTable", []):
                    versions.update({k.decode("utf-8", "replace"): v.decode("utf-8", "replace")
                                     for k, v in table.entries.items()})
        raw_end, tail, cert, cert_size = overlay_info(data, size)
        row.update(machine=pe.FILE_HEADER.Machine, sections=sections, imports=imports,
                   version=versions, certificate_offset=cert, certificate_size=cert_size,
                   noncertificate_overlay_size=tail)
        def add(category, evidence):
            if category not in row["categories"]:
                row["categories"].append(category)
            row["evidence"].append(evidence)
        # Match framework signatures, rather than filenames or words like "setup".
        frameworks = []
        for name, marker in [("NSIS", NSIS_MARKER), ("Inno", b"Inno Setup Setup Data"),
                             ("7-Zip SFX", b"7zS.sfx"), ("RAR SFX", b"Rar!\x1a\x07")]:
            if marker in data:
                frameworks.append(name)
        if b"PythonCore" in data and b"wininst" in data:
            frameworks.append("CPython wininst")
        if frameworks:
            add("安装器或卸载器", "framework=" + ",".join(frameworks))
        if {"UPX0", "UPX1"}.issubset(sections):
            add("UPX加壳", "sections=UPX0,UPX1")
        if (b"krnln.fnr" in data or b"krnln.fne" in data) and (b"GetNewSock" in data or b"Software\\FlySky\\E\\Install" in data):
            add("易语言", "krnln runtime + GetNewSock/FlySky registry")
        if pe.OPTIONAL_HEADER.Subsystem == 1 and (pe.FILE_HEADER.Characteristics & 0x1000 or
                any(d.startswith(("ntoskrnl", "hal.", "wdf", "ndis.")) for d in imports)):
            add("驱动", "native subsystem + system flag/kernel import")
        at = data.find(BUNDLE_MARKER)
        if at >= 8 and 0 < int.from_bytes(data[at-8:at], "little") < size:
            add("NET单文件程序", f"bundle marker at {at}, header={int.from_bytes(data[at-8:at], 'little')}")
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14 and pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress:
            add("NET托管程序", "CLR directory present")
        large = [s.Name.rstrip(b"\0").decode("ascii", "replace") for s in pe.sections
                 if not s.Characteristics & 0x20000000 and s.SizeOfRawData > size * 0.5 and s.get_entropy() > 7.2]
        if large:
            add("大型高熵数据节", ",".join(large))
        rwx = [s.Name.rstrip(b"\0").decode("ascii", "replace") for s in pe.sections
               if s.Characteristics & 0xe0000000 == 0xe0000000]
        if rwx:
            add("含RWX节", ",".join(rwx))
        if tail > size * 0.5 and tail > 65536:
            add("大型非证书尾部", f"noncertificate tail={tail} bytes, raw_end={raw_end}")
        if cert_size and tail == 0:
            add("尾部仅证书", f"validated WIN_CERTIFICATE={cert_size} bytes")
        if not row["categories"]:
            add("其他PE", "no requested structural fingerprint matched")
    refine_vmprotect(row)
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--safe", type=Path, default=Path(r"F:\sliverfox-file\safe"))
    parser.add_argument("--output", type=Path, default=Path("output/safe-classification-2026.10.7"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    for n, path in enumerate(sorted(p for p in args.safe.rglob("*") if p.is_file()), 1):
        try:
            row = classify(path)
        except (OSError, ValueError, IndexError, pefile.PEFormatError) as exc:
            row = {"path": str(path), "categories": ["读取或解析异常"], "evidence": [str(exc)]}
        rows.append(row)
        if n % 500 == 0:
            print(f"classified {n}", flush=True)
    write_reports(rows, args.safe, args.output)


def write_reports(rows, safe, output):
    for row in rows:
        refine_vmprotect(row)
    counts = collections.Counter(c for row in rows for c in row["categories"])
    summary = {"safe_directory": str(safe), "file_count": len(rows),
               "pe_file_count": sum("machine" in row for row in rows),
               "classification": "content-based overlapping structural labels; no file moves",
               "category_counts": dict(counts)}
    (output / "samples.json").write_text(json.dumps({"summary": summary, "samples": rows},
                                                        ensure_ascii=False, indent=2), encoding="utf-8")
    with (output / "samples.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["path", "sha256", "size", "categories", "evidence", "certificate_bytes", "noncertificate_overlay_bytes"])
        for row in rows:
            writer.writerow([row["path"], row.get("sha256", ""), row.get("size", ""),
                             ";".join(row["categories"]), ";".join(row["evidence"]),
                             row.get("certificate_size", ""), row.get("noncertificate_overlay_size", "")])
    lines = ["# 白样本结构分类", "", f"共 {len(rows)} 个文件。分类按内容标记，同一文件可以具有多个标签。", "",
             "|类别|文件数|", "|---|---:|"]
    lines.extend(f"|{name}|{count}|" for name, count in counts.most_common())
    lines += ["", "[逐文件清单](samples.csv) · [完整结构证据](samples.json)", ""]
    (output / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()

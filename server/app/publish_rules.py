import base64
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from sign_program import sign_bytes, verify


def verify_engine_export_version(engine: Path, expected_version: str) -> None:
    if os.name != "nt":
        return
    probe = ("import ctypes, sys; "
             "dll = ctypes.CDLL(sys.argv[1]); "
             "fn = dll.sf_engine_version; fn.argtypes = []; fn.restype = ctypes.c_char_p; "
             "print(fn().decode('ascii'))")
    result = subprocess.run([sys.executable, "-c", probe, str(engine.resolve())],
                            capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"cannot read DLL self-reported version: {result.stderr.strip()}")
    actual = result.stdout.strip()
    if actual != expected_version:
        raise SystemExit(f"DLL self-reported version {actual} differs from signed version {expected_version}")


def sign_engine_section(engine: Path, key: Ed25519PrivateKey, version: str) -> bytes:
    body = engine.read_bytes()
    if len(body) < 1024 or not body.startswith(b"MZ"):
        raise SystemExit("algorithms.dll is not a valid PE image")
    verify_engine_export_version(engine, version)
    from sign_program import signature_offset
    slot = signature_offset(body)
    if any(body[slot + 12:slot + 108]):
        verify(body, key.public_key(), "engine", version)
        return body
    signed = sign_bytes(body, key, key.public_key(), "engine", version)
    verify(signed, key.public_key(), "engine", version)
    engine.write_bytes(signed)
    return signed


def publish(version: str, key: Ed25519PrivateKey, output: Path, public_base_url: str,
            channel: str, engine: Path) -> tuple[Path, Path]:
    if channel not in ("stable", "beta"):
        raise ValueError("invalid channel")
    if not engine.is_file() or engine.stat().st_size < 1024:
        raise ValueError("algorithms.dll is required")
    output.mkdir(parents=True, exist_ok=True)
    signed_engine = sign_engine_section(engine, key, version)
    channel_output = output / channel
    channel_output.mkdir(parents=True, exist_ok=True)
    package = channel_output / f"rules-{version}.zip"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest-version.txt", version)
        archive.writestr("algorithms.dll", signed_engine)
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    signature = base64.b64encode(key.sign(bytes.fromhex(digest))).decode()
    manifest = {"channel": channel, "version": version, "available": True,
                "url": f"{public_base_url.rstrip('/')}/public/rules/{channel}/{package.name}",
                "sha256": digest, "signature": signature, "algorithm": "Ed25519"}
    manifest_path = channel_output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), "utf-8")
    return package, manifest_path


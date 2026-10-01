"""Create a signed runtime package manifest for one SilverFox update channel."""
import base64
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def publish(package: Path, version: str, key: Ed25519PrivateKey, public_url: str,
            output: Path, channel: str, policy: str = "optional", package_query: str = "") -> Path:
    if channel not in ("stable", "beta") or policy not in ("none", "optional", "forced"):
        raise ValueError("invalid channel or update policy")
    digest = hashlib.sha256(package.read_bytes()).digest()
    manifest = {
        "product": "silverfox-rescue", "channel": channel, "available": True,
        "latest_version": version, "policy": policy,
        "package_url": f"{public_url.rstrip('/')}/public/program/{channel}/{package.name}{package_query}",
        "sha256": digest.hex(), "signature": base64.b64encode(key.sign(digest)).decode(),
        "algorithm": "Ed25519", "platform": "windows-x64",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), "utf-8")
    return output


#!/usr/bin/env python3
"""Generate a release Ed25519 key pair in the shared key directory."""

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if __package__:
    from .tool_paths import KEY_DIR
else:
    from tool_paths import KEY_DIR


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("private_key", type=Path, nargs="?")
    parser.add_argument("public_key", type=Path, nargs="?")
    parser.add_argument("--kind", choices=("rules", "program"), default="rules")
    args = parser.parse_args()
    if (args.private_key is None) != (args.public_key is None):
        parser.error("provide both private_key and public_key, or omit both")
    private_path = (args.private_key or KEY_DIR / f"{args.kind}-private.pem").expanduser().resolve()
    public_path = (args.public_key or KEY_DIR / f"{args.kind}-public.hex").expanduser().resolve()
    if private_path == public_path:
        parser.error("private and public keys require separate files")
    if private_path.exists() or public_path.exists():
        parser.error("key files already exist; choose new paths to create a new pair")
    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    with private_path.open("xb") as output:
        output.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # Explicit binary destinations retain the format used by older callers.
    with public_path.open("xb") as output:
        output.write((raw.hex() + "\n").encode("ascii") if public_path.suffix.lower() == ".hex" else raw)
    print(f"Private key: {private_path}\nPublic key: {public_path}")


if __name__ == "__main__":
    main()

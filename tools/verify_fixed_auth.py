"""Exercise the production fixed-key request boundary without printing secrets."""

import argparse
import hashlib
import hmac
import secrets
import time
from pathlib import Path

if __package__:
    from .tool_paths import KEY_DIR
else:
    from tool_paths import KEY_DIR

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def signed_headers(token: str, device_id: str, key: Ed25519PrivateKey) -> dict[str, str]:
    method, path = "GET", "/v1/program/manifest"
    digest = hashlib.sha256(b"").hexdigest()
    timestamp, nonce = str(int(time.time())), secrets.token_hex(24)
    canonical = "\n".join((method, path, digest, timestamp, nonce))
    device_canonical = canonical + "\n" + device_id
    return {
        "Authorization": f"Bearer {token}",
        "X-SF-Timestamp": timestamp,
        "X-SF-Nonce": nonce,
        "X-SF-Content-SHA256": digest,
        "X-SF-Signature": hmac.new(token.encode(), canonical.encode(), hashlib.sha256).hexdigest(),
        "X-SF-Device-ID": device_id,
        "X-SF-Device-Public-Key": key.public_key().public_bytes_raw().hex(),
        "X-SF-Device-Signature": key.sign(device_canonical.encode()).hex(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--cert", type=Path, default=KEY_DIR / "mtls/client-cert.pem")
    parser.add_argument("--key", type=Path, default=KEY_DIR / "mtls/client-key.pem")
    parser.add_argument("--device-id-file", type=Path, default=KEY_DIR / "device-id.txt")
    parser.add_argument("--device-key-file", type=Path, default=KEY_DIR / "device-private.hex")
    parser.add_argument("--token-file", type=Path, default=KEY_DIR / "cloud-token.txt")
    args = parser.parse_args()
    token = args.token_file.read_text().strip()
    device_id = args.device_id_file.read_text().strip()
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(args.device_key_file.read_text().strip()))
    url = args.base_url.rstrip("/") + "/v1/program/manifest"
    with httpx.Client(timeout=15) as unauthenticated:
        no_cert = unauthenticated.get(url)
    with httpx.Client(cert=(str(args.cert), str(args.key)), timeout=15) as client:
        headers = signed_headers(token, device_id, key)
        valid = client.get(url, headers=headers)
        replay = client.get(url, headers=headers)
        forged = client.get(url, headers=signed_headers(token, device_id, Ed25519PrivateKey.generate()))
    result = {"no_cert": no_cert.status_code, "valid": valid.status_code,
              "replay": replay.status_code, "forged_key": forged.status_code}
    print(result)
    if not (no_cert.status_code in {400, 401, 403, 495}
            and valid.status_code == 200 and replay.status_code == 409
            and forged.status_code == 401):
        raise SystemExit("fixed-key production authentication check failed")


if __name__ == "__main__":
    main()

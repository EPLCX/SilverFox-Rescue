"""Select the beta update manifest against the current stable release."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def version(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    if not 1 <= len(parts) <= 8 or any(not p.isascii() or not p.isdecimal() for p in parts):
        raise ValueError("invalid release version")
    return tuple(int(p) for p in parts) + (0,) * (8 - len(parts))


def select_manifest(root: Path, category: str) -> tuple[dict, str]:
    field = "latest_version" if category == "program" else "version"
    candidates = {}
    for channel in ("stable", "beta"):
        try:
            path = root / category / channel / "manifest.json"
            if path.stat().st_size > 65536:
                continue
            manifest = json.loads(path.read_text("utf-8"))
            if manifest["channel"] != channel or not manifest["available"]:
                continue
            candidates[channel] = (version(manifest[field]), manifest)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            continue
    if not candidates:
        raise ValueError("no available update manifest")
    source = "beta" if "beta" in candidates else "stable"
    if "stable" in candidates and candidates["stable"][0] > candidates[source][0]:
        source = "stable"
    manifest = dict(candidates[source][1])
    manifest["channel"] = "beta"
    return manifest, source


def serve(root: Path, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            routes = {"/public/program/beta/manifest.json": "program",
                      "/public/rules/beta/manifest.json": "rules"}
            category = routes.get(self.path.split("?", 1)[0])
            if category is None:
                self.send_error(404)
                return
            try:
                manifest, source = select_manifest(root, category)
                body = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
            except ValueError:
                self.send_error(503, "No available update manifest")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-SilverFox-Source-Channel", source)
            self.end_headers()
            self.wfile.write(body)

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18081)
    args = parser.parse_args()
    serve(args.root, args.port)

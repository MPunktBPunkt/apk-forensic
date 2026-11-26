"""Local stdlib HTTP server for the Forensic Analysis UI (read-only)."""

from __future__ import annotations

import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


STATIC_DIR = Path(__file__).resolve().parent / "static"


class ForensicUIHandler(SimpleHTTPRequestHandler):
    snapshot_path: Path
    snapshot_payload: bytes

    def __init__(self, *args: Any, directory: str | None = None, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/api/snapshot", "/snapshot.json"}:
            data = self.snapshot_payload
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if parsed.path in {"/", "/index.html"}:
            self.path = "/index.html"
        return SimpleHTTPRequestHandler.do_GET(self)


def serve_ui(*, snapshot: Path | dict[str, Any], host: str = "127.0.0.1", port: int = 8765) -> None:
    if isinstance(snapshot, dict):
        payload = json.dumps(snapshot, indent=2, ensure_ascii=False).encode("utf-8")
        snap_path = Path("<memory>")
    else:
        snap_path = Path(snapshot).resolve()
        if not snap_path.is_file():
            raise FileNotFoundError(f"Snapshot not found: {snap_path}")
        payload = snap_path.read_bytes()

    handler = partial(ForensicUIHandler)
    # Bind snapshot onto class for handler instances
    ForensicUIHandler.snapshot_path = snap_path
    ForensicUIHandler.snapshot_payload = payload
    ForensicUIHandler._quiet = True  # type: ignore[attr-defined]

    httpd = ThreadingHTTPServer((host, port), handler)
    print(f"Forensic UI: http://{host}:{port}/")
    print(f"Snapshot: {snap_path}")
    print("Read-only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()

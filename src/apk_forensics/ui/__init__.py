"""Read-only Forensic Analysis UI (snapshot + local static server).

Does not analyze APKs. Does not invent evidence classifications.
"""

from apk_forensics.ui.snapshot import SNAPSHOT_SCHEMA, build_ui_snapshot, load_json
from apk_forensics.ui.server import serve_ui

__all__ = [
    "SNAPSHOT_SCHEMA",
    "build_ui_snapshot",
    "load_json",
    "serve_ui",
]

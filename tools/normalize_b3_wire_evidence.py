#!/usr/bin/env python3
"""CASE-B normalizer: bt-analyzer B3 capture → apk_forensics.wire_evidence.v1 JSON.

No correlation logic. No protocol naming. Writes only neutral wire packets.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from apk_forensics.runtime_wire_evidence import normalize_b3_capture_to_wire_evidence  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("capture_dir", type=Path, help="B3 capture directory with raw/ + optional b3.jsonl")
    ap.add_argument("--output", type=Path, required=True, help="Output wire_evidence JSON path")
    args = ap.parse_args()
    payload = normalize_b3_capture_to_wire_evidence(args.capture_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"status={payload.get('status')} packets={(payload.get('counts') or {}).get('packets')}")
    print(f"wrote {args.output}")
    return 0 if payload.get("status") == "OK" else 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Create a synthetic test APK/ZIP artifact (not a real Android package)."""

from __future__ import annotations

import zipfile
from pathlib import Path

# Synthetic marker strings intentionally embedded for scanner tests.
SYNTHETIC_MARKERS = b"""
SYNTHETIC_TEST_APK_NOT_REAL_ANDROID
createRfcommSocketToServiceRecord
createInsecureRfcommSocketToServiceRecord
fetchUuidsWithSdp
getInputStream
getOutputStream
InputStream
OutputStream
00001101-0000-1000-8000-00805F9B34FB
0x1101
BCL
RHMI
port=4004
socket(5001)
channel 6
android.bluetooth.BluetoothSocket
"""


def create_synthetic_apk(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x00\x00SYNTHETIC_MANIFEST_BINARY")
        zf.writestr("classes.dex", b"dex\n" + SYNTHETIC_MARKERS)
        zf.writestr("classes2.dex", b"dex2\nfetchUuidsWithSdp\nBMW\n")
        zf.writestr(
            "lib/arm64-v8a/libsample.so",
            b"\x7fELF\x02\x01\x01" + b"\x00" * 20 + SYNTHETIC_MARKERS,
        )
        zf.writestr("assets/sample.txt", b"hello synthetic asset\nBCL\n")
        zf.writestr("resources.arsc", b"arsc-synthetic")
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        # Zip-slip candidate for detection tests (not extracted by the tool).
        zf.writestr("../evil.txt", b"zip-slip-test")
    return path


if __name__ == "__main__":
    out = Path(__file__).with_name("sample.apk")
    create_synthetic_apk(out)
    print(out)

"""Generic Artifact / ArtifactBundle model for base APK + configuration splits.

Naming:
- Artifact: one APK file (base or split), the atomic analysis object
- ArtifactBundle: correlated set of Artifacts sharing package/version evidence
- Split: non-base member (ABI / density / locale / feature)

Correlation never relies on filenames alone. Insufficient evidence → UNKNOWN.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from apk_forensics.hashing import file_sha256_and_size

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Weak filename hints only — never sufficient alone for FACT correlation
_SPLIT_NAME_RE = re.compile(
    r"^(?P<prefix>.+?)[\._-](?P<kind>config\.(?P<config>[A-Za-z0-9_]+)|split\.(?P<split>[A-Za-z0-9_.-]+))\.apk$",
    re.IGNORECASE,
)
_ABI_MAP = {
    "arm64_v8a": "arm64-v8a",
    "armeabi_v7a": "armeabi-v7a",
    "armeabi": "armeabi",
    "x86_64": "x86_64",
    "x86": "x86",
}
_DENSITY_TOKENS = {
    "ldpi",
    "mdpi",
    "hdpi",
    "xhdpi",
    "xxhdpi",
    "xxxhdpi",
    "tvdpi",
    "nodpi",
    "anydpi",
}


@dataclass
class ArtifactIdentity:
    path: str
    file_name: str
    sha256: str
    size_bytes: int


@dataclass
class ArtifactMeta:
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    split_name: str | None = None
    is_feature_split: bool | None = None
    abi: str | None = None
    density: str | None = None
    locale: str | None = None
    role: str = "unknown"  # base | split | unknown
    evidence: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)


@dataclass
class Artifact:
    identity: ArtifactIdentity
    meta: ArtifactMeta

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": asdict(self.identity),
            "meta": asdict(self.meta),
        }


@dataclass
class ArtifactBundle:
    bundle_id: str
    correlation_status: str  # correlated | partial | unknown | singleton
    correlation_reasons: list[str] = field(default_factory=list)
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    base: Artifact | None = None
    splits: list[Artifact] = field(default_factory=list)
    members: list[Artifact] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "correlation_status": self.correlation_status,
            "correlation_reasons": self.correlation_reasons,
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "base": self.base.to_dict() if self.base else None,
            "splits": [s.to_dict() for s in self.splits],
            "members": [m.to_dict() for m in self.members],
            "unknowns": self.unknowns,
        }


def _attr(elem: ET.Element, name: str) -> str | None:
    return elem.attrib.get(f"{ANDROID_NS}{name}") or elem.attrib.get(name)


def _read_binary_manifest_via_androguard(apk_path: Path) -> dict[str, Any] | None:
    try:
        from androguard.core.apk import APK  # type: ignore
        from androguard.util import set_log  # type: ignore

        try:
            set_log("CRITICAL")
        except Exception:
            pass
        apk = APK(str(apk_path))
        split = None
        try:
            if hasattr(apk, "get_split_name"):
                split = apk.get_split_name()
        except Exception:
            split = None
        if not split:
            try:
                xml = apk.get_android_manifest_xml()
                # Split APKs often store android:split without the namespace prefix
                split = (
                    xml.attrib.get(f"{ANDROID_NS}split")
                    or xml.attrib.get("split")
                    or None
                )
            except Exception:
                split = None
        return {
            "package_name": apk.get_package() or None,
            "version_name": apk.get_androidversion_name() or None,
            "version_code": str(apk.get_androidversion_code()) if apk.get_androidversion_code() is not None else None,
            "split_name": split or None,
            "source": "androguard",
        }
    except Exception:
        return None


def _read_xml_manifest_from_zip(apk_path: Path) -> dict[str, Any] | None:
    """Fallback for plain XML AndroidManifest (rare in production APKs)."""
    try:
        with zipfile.ZipFile(apk_path) as zf:
            data = zf.read("AndroidManifest.xml")
    except Exception:
        return None
    # Binary AXML starts with non-printable; skip if not XML
    if not data.lstrip().startswith(b"<?xml") and not data.lstrip().startswith(b"<manifest"):
        return None
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return None
    return {
        "package_name": root.attrib.get("package"),
        "version_name": _attr(root, "versionName"),
        "version_code": _attr(root, "versionCode"),
        "split_name": _attr(root, "split"),
        "source": "xml",
    }


def _filename_hints(file_name: str) -> dict[str, Any]:
    hints: dict[str, Any] = {"confidence": "weak", "source": "filename"}
    lower = file_name.lower()
    m = _SPLIT_NAME_RE.match(file_name)
    if m:
        config = m.group("config") or m.group("split")
        if config:
            hints["split_token"] = config
            abi_key = config.replace("-", "_")
            if abi_key in _ABI_MAP or config in _ABI_MAP.values():
                hints["abi"] = _ABI_MAP.get(abi_key, config)
                hints["kind"] = "abi"
            elif config.lower() in _DENSITY_TOKENS:
                hints["density"] = config.lower()
                hints["kind"] = "density"
            elif len(config) <= 6 and config.replace("-", "").isalpha():
                hints["locale"] = config
                hints["kind"] = "locale"
            else:
                hints["kind"] = "config"
    if "config." in lower or ".split." in lower or lower.startswith("split_"):
        hints["suggests_split"] = True
    return hints


def _infer_abi_from_native(apk_path: Path) -> str | None:
    try:
        with zipfile.ZipFile(apk_path) as zf:
            abis = set()
            for name in zf.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    if len(parts) >= 3:
                        abis.add(parts[1])
            if len(abis) == 1:
                return next(iter(abis))
    except Exception:
        return None
    return None


def inspect_artifact(path: Path) -> Artifact:
    path = path.resolve()
    sha256, size_bytes = file_sha256_and_size(path)
    identity = ArtifactIdentity(
        path=str(path),
        file_name=path.name,
        sha256=sha256,
        size_bytes=size_bytes,
    )
    meta = ArtifactMeta()
    evidence: list[dict[str, Any]] = []

    ag = _read_binary_manifest_via_androguard(path)
    if ag:
        meta.package_name = ag.get("package_name")
        meta.version_name = ag.get("version_name")
        meta.version_code = ag.get("version_code")
        meta.split_name = ag.get("split_name") or None
        evidence.append({"type": "manifest", "status": "FACT", "source": "androguard", "data": ag})
    else:
        xml = _read_xml_manifest_from_zip(path)
        if xml:
            meta.package_name = xml.get("package_name")
            meta.version_name = xml.get("version_name")
            meta.version_code = xml.get("version_code")
            meta.split_name = xml.get("split_name")
            evidence.append({"type": "manifest", "status": "FACT", "source": "xml", "data": xml})
        else:
            meta.unknowns.append("manifest_metadata_unavailable")
            evidence.append({"type": "manifest", "status": "UNKNOWN", "reason": "could not parse AndroidManifest.xml"})

    hints = _filename_hints(path.name)
    evidence.append({"type": "filename_hint", "status": "INFERENCE", "data": hints})

    abi = _infer_abi_from_native(path)
    if abi:
        meta.abi = abi
        evidence.append({"type": "native_abi", "status": "FACT", "abi": abi})

    if meta.split_name:
        meta.role = "split"
        # Parse config.arm64_v8a style split names
        sn = meta.split_name
        if sn.startswith("config."):
            token = sn[len("config.") :]
            abi_key = token.replace("-", "_")
            if abi_key in _ABI_MAP:
                meta.abi = meta.abi or _ABI_MAP[abi_key]
            elif token.lower() in _DENSITY_TOKENS:
                meta.density = token.lower()
            elif len(token) <= 6:
                meta.locale = token
    elif meta.package_name and not hints.get("suggests_split"):
        # No split attribute → likely base (FACT from manifest absence of split)
        meta.role = "base"
        evidence.append({"type": "role", "status": "FACT", "role": "base", "reason": "no splitName in manifest"})
    elif hints.get("suggests_split"):
        meta.role = "unknown"
        meta.unknowns.append("role_filename_suggests_split_but_manifest_incomplete")
        evidence.append(
            {
                "type": "role",
                "status": "UNKNOWN",
                "reason": "filename suggests split but manifest splitName unavailable/empty",
            }
        )
    else:
        meta.role = "unknown"
        meta.unknowns.append("role_not_determined")

    # Density/locale from filename only as weak meta when split_name absent
    if not meta.abi and hints.get("abi"):
        meta.abi = hints["abi"]
        meta.unknowns.append("abi_from_filename_only")
    if not meta.density and hints.get("density"):
        meta.density = hints["density"]
        meta.unknowns.append("density_from_filename_only")
    if not meta.locale and hints.get("locale"):
        meta.locale = hints["locale"]
        meta.unknowns.append("locale_from_filename_only")

    meta.evidence = evidence
    return Artifact(identity=identity, meta=meta)


def _same_identity_keys(a: Artifact, b: Artifact) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if not a.meta.package_name or not b.meta.package_name:
        return False, ["package_name_missing"]
    if a.meta.package_name != b.meta.package_name:
        return False, [f"package_mismatch:{a.meta.package_name}!={b.meta.package_name}"]
    reasons.append(f"package_name={a.meta.package_name}")

    if a.meta.version_code and b.meta.version_code:
        if a.meta.version_code != b.meta.version_code:
            return False, [f"version_code_mismatch:{a.meta.version_code}!={b.meta.version_code}"]
        reasons.append(f"version_code={a.meta.version_code}")
    else:
        return False, ["version_code_missing"]

    if a.meta.version_name and b.meta.version_name and a.meta.version_name != b.meta.version_name:
        return False, [f"version_name_mismatch:{a.meta.version_name}!={b.meta.version_name}"]
    if a.meta.version_name and b.meta.version_name:
        reasons.append(f"version_name={a.meta.version_name}")

    return True, reasons


def correlate_artifacts(artifacts: list[Artifact]) -> ArtifactBundle:
    """Correlate artifacts into a bundle or report UNKNOWN / non-merge."""
    if not artifacts:
        return ArtifactBundle(
            bundle_id="empty",
            correlation_status="unknown",
            unknowns=["no_artifacts"],
        )

    if len(artifacts) == 1:
        a = artifacts[0]
        return ArtifactBundle(
            bundle_id=f"singleton:{a.identity.sha256[:12]}",
            correlation_status="singleton",
            correlation_reasons=["single_artifact"],
            package_name=a.meta.package_name,
            version_name=a.meta.version_name,
            version_code=a.meta.version_code,
            base=a if a.meta.role == "base" else (a if a.meta.role != "split" else None),
            splits=[a] if a.meta.role == "split" else [],
            members=list(artifacts),
        )

    # Pairwise check against first usable anchor
    anchor = artifacts[0]
    all_reasons: list[str] = []
    mismatches: list[str] = []
    for other in artifacts[1:]:
        ok, reasons = _same_identity_keys(anchor, other)
        if ok:
            all_reasons.extend(reasons)
        else:
            mismatches.extend(reasons)

    if mismatches:
        return ArtifactBundle(
            bundle_id="unmerged",
            correlation_status="unknown",
            correlation_reasons=[],
            members=list(artifacts),
            unknowns=["artifacts_not_correlated"] + mismatches,
        )

    # Deduplicate reasons
    uniq_reasons = list(dict.fromkeys(all_reasons))
    bases = [a for a in artifacts if a.meta.role == "base"]
    splits = [a for a in artifacts if a.meta.role == "split"]
    unknowns_role = [a for a in artifacts if a.meta.role == "unknown"]

    base: Artifact | None = None
    status = "correlated"
    unknowns: list[str] = []

    if len(bases) == 1:
        base = bases[0]
    elif len(bases) == 0:
        # If exactly one non-split and others are splits, treat as base
        non_split = [a for a in artifacts if a.meta.role != "split"]
        if len(non_split) == 1 and splits:
            base = non_split[0]
            base.meta.role = "base"
            uniq_reasons.append("base_inferred_as_sole_non_split")
            status = "partial"
            unknowns.append("base_role_inferred")
        elif len(artifacts) == 2 and len(splits) == 1:
            base = next(a for a in artifacts if a is not splits[0])
            base.meta.role = "base"
            uniq_reasons.append("base_inferred_as_counterpart_of_split")
            status = "partial"
            unknowns.append("base_role_inferred")
        else:
            status = "partial"
            unknowns.append("base_not_identified")
    else:
        status = "unknown"
        unknowns.append("multiple_base_candidates")
        return ArtifactBundle(
            bundle_id="unmerged",
            correlation_status="unknown",
            members=list(artifacts),
            unknowns=unknowns,
        )

    # After base is known, remaining correlated members without role → treat as splits (partial)
    if base is not None:
        for member in artifacts:
            if member is base:
                continue
            if member.meta.role == "unknown":
                member.meta.role = "split"
                member.meta.unknowns.append("role_inferred_as_non_base_bundle_member")
                unknowns.append(f"split_role_inferred:{member.identity.file_name}")
                status = "partial"
        splits = [a for a in artifacts if a is not base]

    if unknowns_role and status == "correlated":
        # roles may have been refined above
        if any(a.meta.role == "unknown" for a in artifacts):
            status = "partial"
            unknowns.append("some_members_role_unknown")

    pkg = anchor.meta.package_name
    vc = anchor.meta.version_code
    # Prefer base version_name when split omits it
    vn = (base.meta.version_name if base and base.meta.version_name else None) or anchor.meta.version_name
    bid = f"bundle:{pkg}:{vc}:{(base or anchor).identity.sha256[:8]}"

    return ArtifactBundle(
        bundle_id=bid,
        correlation_status=status,
        correlation_reasons=uniq_reasons,
        package_name=pkg,
        version_name=vn,
        version_code=vc,
        base=base,
        splits=splits,
        members=list(artifacts),
        unknowns=list(dict.fromkeys(unknowns)),
    )


def discover_bundle_candidates(paths: list[Path]) -> ArtifactBundle:
    artifacts = [inspect_artifact(p) for p in paths]
    return correlate_artifacts(artifacts)


def load_paths_from_bundle_arg(bundle_arg: str) -> list[Path]:
    """Accept a directory of APKs or a single path."""
    p = Path(bundle_arg)
    if p.is_dir():
        apks = sorted(p.glob("*.apk"))
        if not apks:
            raise FileNotFoundError(f"No APK files in bundle directory: {p}")
        return apks
    if p.is_file():
        return [p]
    raise FileNotFoundError(f"Bundle path not found: {p}")

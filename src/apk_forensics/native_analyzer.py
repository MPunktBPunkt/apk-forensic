"""Native shared-object inventory with optional ELF parsing."""

from __future__ import annotations

import zipfile
from typing import Any

from apk_forensics.candidate_scanner import ScanBlob
from apk_forensics.config import AnalysisConfig
from apk_forensics.finding_factory import make_finding
from apk_forensics.hashing import bytes_sha256
from apk_forensics.models import AnalysisStatus, Classification, Confidence, ScannerResult
from apk_forensics.string_scanner import extract_strings
from apk_forensics.utils import abi_from_lib_path, timed_ms


def _parse_elf(data: bytes) -> tuple[dict[str, Any], bool, str | None]:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        from io import BytesIO
    except Exception:
        return (
            {
                "parse_status": "unavailable",
                "class": None,
                "endianness": None,
                "machine": None,
                "machine_code": None,
                "entry_point": None,
                "section_names": [],
                "needed_libraries": [],
                "exported_symbols": [],
                "imported_symbols": [],
            },
            True,
            None,
        )

    try:
        elf = ELFFile(BytesIO(data))
        section_names = [s.name for s in elf.iter_sections() if s.name]
        needed: list[str] = []
        exported: list[str] = []
        imported: list[str] = []
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic is not None:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)
        symtab = elf.get_section_by_name(".dynsym")
        if symtab is not None:
            for sym in symtab.iter_symbols():
                name = sym.name
                if not name:
                    continue
                if sym.entry.st_shndx == "SHN_UNDEF":
                    imported.append(name)
                else:
                    exported.append(name)
        return (
            {
                "parse_status": "parsed",
                "class": "ELF64" if elf.elfclass == 64 else "ELF32",
                "endianness": "little" if elf.little_endian else "big",
                "machine": elf.get_machine_arch(),
                "machine_code": elf["e_machine"],
                "entry_point": elf["e_entry"],
                "section_names": section_names[:200],
                "needed_libraries": needed[:200],
                "exported_symbols": exported[:200],
                "imported_symbols": imported[:200],
            },
            False,
            None,
        )
    except Exception as exc:  # noqa: BLE001
        return (
            {
                "parse_status": "failed",
                "class": None,
                "endianness": None,
                "machine": None,
                "machine_code": None,
                "entry_point": None,
                "section_names": [],
                "needed_libraries": [],
                "exported_symbols": [],
                "imported_symbols": [],
            },
            False,
            str(exc),
        )


def analyze_native(
    zf: zipfile.ZipFile,
    *,
    artifact_sha256: str,
    config: AnalysisConfig | None = None,
) -> ScannerResult:
    cfg = config or AnalysisConfig()
    with timed_ms() as timing:
        inventory: list[dict[str, Any]] = []
        blobs: list[ScanBlob] = []
        findings = []
        warnings: list[str] = []
        errors: list[str] = []
        optional_missing = False

        so_names = sorted(
            info.filename
            for info in zf.infolist()
            if not info.is_dir()
            and info.filename.replace("\\", "/").startswith("lib/")
            and info.filename.lower().endswith(".so")
        )

        for name in so_names:
            path = name.replace("\\", "/")
            entry: dict[str, Any] = {
                "path": path,
                "abi": abi_from_lib_path(path),
                "size_bytes": None,
                "sha256": None,
                "elf": {},
                "strings": [],
                "findings": [],
            }
            try:
                info = zf.getinfo(name)
                entry["size_bytes"] = info.file_size
                if info.file_size > cfg.max_entry_read_bytes:
                    warnings.append(f"Native library too large for full read: {path}")
                    entry["elf"] = {"parse_status": "skipped"}
                    inventory.append(entry)
                    continue
                raw = zf.read(name)
                entry["sha256"] = bytes_sha256(raw)
                elf_info, missing, err = _parse_elf(raw)
                entry["elf"] = elf_info
                if missing:
                    optional_missing = True
                if err:
                    warnings.append(f"ELF parse failed for {path}: {err}")

                strings = extract_strings(raw, config=cfg)
                # Keep only a compact preview in inventory
                entry["strings"] = [
                    {
                        "value": s.value[:120],
                        "encoding": s.encoding,
                        "offset": s.offset,
                        "length": s.length,
                    }
                    for s in strings[:50]
                ]
                blobs.append(ScanBlob(entry=path, file_type="native", data=raw))

                finding = make_finding(
                    artifact_sha256=artifact_sha256,
                    kind="native_library",
                    category="native",
                    subcategory="native.library",
                    value=path,
                    normalized_value=path,
                    classification=Classification.FACT.value,
                    confidence=Confidence.HIGH.value,
                    source_entry=path,
                    file_type="native",
                    offset=None,
                    length=len(raw),
                    matched_text=path,
                    scanner="native_analyzer",
                    tags=["native", entry["abi"] or "unknown-abi"],
                    notes=["Native library presence only; no disassembly performed."],
                )
                findings.append(finding)
                entry["findings"].append(finding.id)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Failed to analyze native library {name}: {exc}")
            inventory.append(entry)

        if optional_missing:
            warnings.append(
                "pyelftools not installed; ELF metadata unavailable. "
                "Path/ABI/size/hash/string candidates remain available."
            )

        status = AnalysisStatus.COMPLETE.value
        if warnings:
            status = AnalysisStatus.PARTIAL.value

    return ScannerResult(
        name="native_analyzer",
        status=status,
        duration_ms=timing["duration_ms"],
        warnings=warnings,
        errors=errors,
        optional_dependency_missing=optional_missing,
        data={"inventory": inventory, "blobs": blobs},
        findings=findings,
    )

"""Androguard compatibility adapter for DEX context analysis."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from apk_forensics.hashing import bytes_sha256


def _silence_androguard_logging() -> None:
    for name in (
        "androguard",
        "androguard.core",
        "androguard.core.dex",
        "androguard.core.analysis",
        "androguard.core.analysis.analysis",
        "androguard.core.apk",
    ):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    # androguard 4.x uses loguru
    try:
        from loguru import logger as loguru_logger

        loguru_logger.disable("androguard")
    except Exception:
        pass


def is_androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
        from androguard.core.dex import DEX  # noqa: F401

        return True
    except Exception:
        return False


def get_androguard_version() -> str | None:
    if not is_androguard_available():
        return None
    try:
        import androguard

        return getattr(androguard, "__version__", "unknown")
    except Exception:
        return "unknown"


CLASS_DESC_RE = re.compile(r"^L([^;]+);$")
METHOD_REF_RE = re.compile(
    r"^(?P<class>L[^;]+;)->(?P<name>[^(]+)\((?P<params>[^)]*)\)(?P<ret>.+)$"
)


def normalize_class_name(raw: str | None) -> str | None:
    if not raw:
        return None
    text = raw.strip()
    match = CLASS_DESC_RE.match(text)
    if match:
        return match.group(1).replace("/", ".")
    if text.startswith("L") and text.endswith(";") and "/" in text:
        return text[1:-1].replace("/", ".")
    return text.replace("/", ".")


def parse_method_ref(raw: str) -> dict[str, str | None]:
    text = raw.strip()
    match = METHOD_REF_RE.match(text)
    if not match:
        compact = re.sub(r"\s+", "", text)
        match = METHOD_REF_RE.match(compact)
        if not match:
            return {
                "class_name": None,
                "method_name": None,
                "descriptor": None,
                "raw": raw,
            }
    class_raw = match.group("class")
    descriptor = f"({match.group('params')}){match.group('ret')}"
    return {
        "class_name": normalize_class_name(class_raw),
        "method_name": match.group("name"),
        "descriptor": descriptor,
        "raw": raw,
    }


@dataclass
class InstructionInfo:
    index: int
    offset: int | None
    opcode: str
    text: str
    registers: list[str] = field(default_factory=list)
    operands: list[str] = field(default_factory=list)
    referenced_method: dict[str, str | None] | None = None
    referenced_string: str | None = None
    referenced_class: str | None = None
    referenced_field: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "offset": self.offset,
            "opcode": self.opcode,
            "text": self.text,
            "registers": list(self.registers),
            "operands": list(self.operands),
            "referenced_method": self.referenced_method,
            "referenced_string": self.referenced_string,
            "referenced_class": self.referenced_class,
            "referenced_field": self.referenced_field,
        }


@dataclass
class MethodInfo:
    dex_entry: str
    class_name: str
    class_name_normalized: str | None
    method_name: str
    method_descriptor: str
    access_flags: list[str]
    is_external: bool
    code_present: bool
    instruction_count: int
    code_offset: int | None
    instructions: list[InstructionInfo] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.class_name}->{self.method_name}{self.method_descriptor}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "dex_entry": self.dex_entry,
            "class_name": self.class_name,
            "class_name_normalized": self.class_name_normalized,
            "method_name": self.method_name,
            "method_descriptor": self.method_descriptor,
            "access_flags": list(self.access_flags),
            "is_external": self.is_external,
            "code_present": self.code_present,
            "instruction_count": self.instruction_count,
            "code_offset": self.code_offset,
        }


@dataclass
class DexUnit:
    entry: str
    sha256: str
    size_bytes: int
    parse_status: str
    parser: dict[str, str]
    class_count: int
    method_count: int
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "parse_status": self.parse_status,
            "parser": dict(self.parser),
            "class_count": self.class_count,
            "method_count": self.method_count,
            "warnings": list(self.warnings),
        }


@dataclass
class DexSession:
    """DEX analysis session with matched/hydrated methods only (memory-safe)."""

    units: list[DexUnit]
    methods: list[MethodInfo]
    parser_name: str = "androguard"
    parser_version: str | None = None
    warnings: list[str] = field(default_factory=list)
    methods_indexed: int = 0
    _raw_analysis: Any = None


def _instruction_from_androguard(index: int, ins: Any) -> InstructionInfo:
    opcode = ""
    try:
        opcode = ins.get_name() or ""
    except Exception:
        opcode = ""
    try:
        output = ins.get_output() or ""
    except Exception:
        output = ""
    text = f"{opcode} {output}".strip()
    offset = None
    if hasattr(ins, "get_offset"):
        try:
            value = ins.get_offset()
            if isinstance(value, int):
                offset = value
        except Exception:
            offset = None

    operands: list[str] = []
    registers: list[str] = []
    try:
        ops = ins.get_operands() or []
        for op in ops:
            operands.append(str(op))
            # Androguard operand tuples often look like: (<Operand.REGISTER: 0>, 5)
            mreg = re.search(r"Operand\.REGISTER[^,]*,\s*(\d+)", str(op))
            if mreg:
                registers.append(f"v{mreg.group(1)}")
            elif isinstance(op, tuple) and len(op) >= 2 and "REGISTER" in str(op[0]):
                registers.append(f"v{op[1]}")
    except Exception:
        pass
    # Fallback: parse vN from text
    if not registers:
        registers = re.findall(r"\bv\d+\b", text)

    referenced_method = None
    referenced_string = None
    referenced_class = None
    referenced_field = None

    if opcode.startswith("invoke"):
        m = re.search(r"(L[^;\s]+;->[^(]+\([^)]*\)[^,\s]*)", text)
        if m:
            referenced_method = parse_method_ref(m.group(1))
    elif opcode.startswith("const-string"):
        m = re.search(r'"((?:\\.|[^"\\])*)"', text)
        if m:
            referenced_string = m.group(1)
        else:
            parts = text.split(",", 1)
            if len(parts) == 2:
                referenced_string = parts[1].strip().strip('"')
    elif opcode in {"new-instance", "check-cast", "const-class"}:
        m = re.search(r"(L[^;\s]+;)", text)
        if m:
            referenced_class = m.group(1)
    elif opcode.startswith(("iget", "iput", "sget", "sput")):
        # Androguard may format fields as: Lcls;->name Type  OR Lcls;->name:Type
        m = re.search(r"(L[^;\s]+;->[^\s,]+(?:\s+|:)[^\s,]+)", text)
        if m:
            referenced_field = re.sub(r"\s+", " ", m.group(1)).strip()
        else:
            for op in operands:
                mf = re.search(r"(L[^';]+;->[^']+)", op)
                if mf:
                    referenced_field = mf.group(1).strip().strip("'\"")
                    break

    return InstructionInfo(
        index=index,
        offset=offset,
        opcode=opcode,
        text=text,
        registers=registers,
        operands=operands,
        referenced_method=referenced_method,
        referenced_string=referenced_string,
        referenced_class=referenced_class,
        referenced_field=referenced_field,
    )


def _method_instructions(encoded_method: Any) -> tuple[list[InstructionInfo], int | None]:
    instructions: list[InstructionInfo] = []
    code_offset = None
    try:
        code = encoded_method.get_code()
    except Exception:
        return [], None
    if code is None:
        return [], None
    try:
        if hasattr(code, "get_off"):
            off = code.get_off()
            if isinstance(off, int):
                code_offset = off
    except Exception:
        code_offset = None
    try:
        bc = code.get_bc()
        raw_ins = list(bc.get_instructions())
    except Exception:
        return [], code_offset
    for idx, ins in enumerate(raw_ins):
        instructions.append(_instruction_from_androguard(idx, ins))
    return instructions, code_offset


def _method_meta(entry: str, encoded: Any, instructions: list[InstructionInfo], code_offset: int | None) -> MethodInfo:
    class_name = encoded.get_class_name()
    method_name = encoded.get_name()
    descriptor = encoded.get_descriptor()
    access: list[str] = []
    try:
        access_str = encoded.get_access_flags_string() or ""
        access = [p for p in access_str.replace(",", " ").split() if p]
    except Exception:
        access = []
    return MethodInfo(
        dex_entry=entry,
        class_name=class_name,
        class_name_normalized=normalize_class_name(class_name),
        method_name=method_name,
        method_descriptor=descriptor,
        access_flags=access,
        is_external=False,
        code_present=bool(instructions),
        instruction_count=len(instructions),
        code_offset=code_offset,
        instructions=instructions,
    )


def iter_encoded_methods(
    dex_entries: list[tuple[str, bytes]],
) -> tuple[list[DexUnit], Iterator[tuple[str, Any, Any]], list[str], str]:
    """Parse DEX units and yield (entry, dex_obj, encoded_method) without keeping all instructions."""
    if not is_androguard_available():
        raise RuntimeError(
            "DEX context analysis requires the optional dependency 'androguard'.\n"
            "Install with:\n"
            "  pip install 'apk-forensics[android]'"
        )
    _silence_androguard_logging()
    from androguard.core.dex import DEX

    version = get_androguard_version() or "unknown"
    units: list[DexUnit] = []
    warnings: list[str] = []
    parsed: list[tuple[str, Any]] = []

    for entry, data in dex_entries:
        try:
            dex = DEX(data)
            parsed.append((entry, dex))
            units.append(
                DexUnit(
                    entry=entry,
                    sha256=bytes_sha256(data),
                    size_bytes=len(data),
                    parse_status="complete",
                    parser={"name": "androguard", "version": version},
                    class_count=int(dex.get_len_classes()),
                    method_count=int(dex.get_len_encoded_methods()),
                )
            )
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Failed to parse DEX '{entry}': {exc}")
            units.append(
                DexUnit(
                    entry=entry,
                    sha256=bytes_sha256(data),
                    size_bytes=len(data),
                    parse_status="failed",
                    parser={"name": "androguard", "version": version},
                    class_count=0,
                    method_count=0,
                    warnings=[str(exc)],
                )
            )

    def _gen() -> Iterator[tuple[str, Any, Any]]:
        for entry, dex in parsed:
            try:
                for encoded in dex.get_encoded_methods():
                    yield entry, dex, encoded
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Failed to iterate methods in {entry}: {exc}")

    return units, _gen(), warnings, version


def stream_methods_with_instructions(
    dex_entries: list[tuple[str, bytes]],
) -> tuple[list[DexUnit], Iterator[MethodInfo], list[str], str]:
    units, encoded_iter, warnings, version = iter_encoded_methods(dex_entries)

    def _gen() -> Iterator[MethodInfo]:
        for entry, _dex, encoded in encoded_iter:
            try:
                instructions, code_offset = _method_instructions(encoded)
                if not instructions:
                    continue
                yield _method_meta(entry, encoded, instructions, code_offset)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"Failed to read method in {entry}: {exc}")

    return units, _gen(), warnings, version


def load_dex_session_from_bytes(
    dex_entries: list[tuple[str, bytes]],
    *,
    keep_method: Callable[[MethodInfo], bool] | None = None,
    max_methods_with_code: int | None = None,
) -> DexSession:
    """Load DEX methods, keeping instructions only for selected methods.

    By default keeps all methods with code (suitable for small fixtures).
    For large APKs prefer streaming match helpers instead.
    """
    units, method_iter, warnings, version = stream_methods_with_instructions(dex_entries)
    methods: list[MethodInfo] = []
    indexed = 0
    for method in method_iter:
        indexed += 1
        if keep_method is not None and not keep_method(method):
            continue
        methods.append(method)
        if max_methods_with_code is not None and len(methods) >= max_methods_with_code:
            break

    warnings.append(
        "External method inventory uses class-prefix heuristics; "
        "full androguard Analysis XREF graph is not built in v0.2."
    )
    return DexSession(
        units=units,
        methods=methods,
        parser_name="androguard",
        parser_version=version,
        warnings=warnings,
        methods_indexed=indexed,
    )


def load_dex_entries_from_apk(apk_path: Path, *, max_entry_bytes: int) -> list[tuple[str, bytes]]:
    import zipfile

    entries: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        dex_names = sorted(
            n
            for n in zf.namelist()
            if n.split("/")[-1].lower().startswith("classes") and n.lower().endswith(".dex")
        )
        for name in dex_names:
            info = zf.getinfo(name)
            if info.file_size > max_entry_bytes:
                continue
            entries.append((name, zf.read(name)))
    return entries


def load_dex_session_from_apk(apk_path: Path, *, max_entry_bytes: int) -> DexSession:
    return load_dex_session_from_bytes(load_dex_entries_from_apk(apk_path, max_entry_bytes=max_entry_bytes))


def iter_internal_methods(session: DexSession) -> Iterator[MethodInfo]:
    for method in session.methods:
        if not method.is_external:
            yield method


def method_window(
    method: MethodInfo,
    match_index: int,
    *,
    window: int,
) -> dict[str, list[dict[str, Any]]]:
    window = max(0, min(100, window))
    before = [
        ins.to_dict()
        for ins in method.instructions[max(0, match_index - window) : match_index]
    ]
    match = [method.instructions[match_index].to_dict()] if 0 <= match_index < len(method.instructions) else []
    after = [
        ins.to_dict()
        for ins in method.instructions[match_index + 1 : match_index + 1 + window]
    ]
    return {"before": before, "match": match, "after": after}

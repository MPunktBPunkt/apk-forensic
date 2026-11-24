"""Typed data models for apk-forensics reports and findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Classification(str, Enum):
    FACT = "FACT"
    CORRELATION = "CORRELATION"
    INFERENCE = "INFERENCE"
    UNKNOWN = "UNKNOWN"
    REJECTED = "REJECTED"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class AnalysisStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class FindingKind(str, Enum):
    STRING = "string"
    UUID = "uuid"
    PORT = "port"
    API = "api"
    PERMISSION = "permission"
    NATIVE_LIBRARY = "native_library"
    PROFILE_MATCH = "profile_match"


def _enum_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    return value


def to_plain(obj: Any) -> Any:
    """Convert nested dataclasses/enums to JSON-serializable structures."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, list):
        return [to_plain(item) for item in obj]
    if isinstance(obj, dict):
        return {key: to_plain(value) for key, value in obj.items()}
    if dataclass_instance(obj):
        return {key: to_plain(value) for key, value in asdict(obj).items()}
    return obj


def dataclass_instance(obj: Any) -> bool:
    return hasattr(obj, "__dataclass_fields__")


@dataclass
class SourceRef:
    entry: str
    file_type: str | None = None
    offset: int | None = None
    length: int | None = None
    section: str | None = None
    class_name: str | None = None
    method_name: str | None = None
    # Artifact provenance (which APK file within a bundle)
    artifact: str | None = None
    artifact_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "entry": self.entry,
            "file_type": self.file_type,
            "offset": self.offset,
            "length": self.length,
            "section": self.section,
            "class_name": self.class_name,
            "method_name": self.method_name,
        }
        if self.artifact is not None:
            payload["artifact"] = self.artifact
        if self.artifact_sha256 is not None:
            payload["artifact_sha256"] = self.artifact_sha256
        return payload


@dataclass
class Evidence:
    matched_text: str
    context_before: str = ""
    context_after: str = ""
    pattern: str | None = None
    scanner: str = ""
    scanner_version: str = "0.1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProfileMatchRef:
    profile: str
    profile_confidence: str
    category: str
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    display_id: str
    kind: str
    category: str
    subcategory: str | None
    value: str
    normalized_value: str
    classification: str
    confidence: str
    source: SourceRef
    evidence: Evidence
    profile_matches: list[ProfileMatchRef] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    context_ids: list[str] = field(default_factory=list)
    context_status: str | None = None
    bluetooth_path_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "display_id": self.display_id,
            "kind": _enum_value(self.kind),
            "category": self.category,
            "subcategory": self.subcategory,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "classification": _enum_value(self.classification),
            "confidence": _enum_value(self.confidence),
            "source": self.source.to_dict(),
            "evidence": self.evidence.to_dict(),
            "profile_matches": [pm.to_dict() for pm in self.profile_matches],
            "tags": list(self.tags),
            "notes": list(self.notes),
        }
        if self.context_status is not None:
            payload["context_status"] = self.context_status
            payload["context_ids"] = list(self.context_ids)
        if self.bluetooth_path_ids:
            payload["bluetooth_path_ids"] = list(self.bluetooth_path_ids)
        return payload


@dataclass
class ScannerResult:
    name: str
    status: str = AnalysisStatus.COMPLETE.value
    duration_ms: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    optional_dependency_missing: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "optional_dependency_missing": self.optional_dependency_missing,
        }


@dataclass
class ZipEntryInfo:
    name: str
    size_bytes: int
    compressed_size_bytes: int
    compression: str
    crc32: str
    sha256: str | None = None
    is_directory: bool = False
    entry_type: str = "other"
    suspicious: bool = False
    suspicion_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolInfo:
    name: str
    version: str
    python_version: str
    platform: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InputInfo:
    path: str
    file_name: str
    size_bytes: int
    sha256: str
    is_readable: bool
    is_zip: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ArtifactInfo:
    type: str = "apk"
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    role: str | None = None
    split_name: str | None = None
    sha256: str | None = None
    file_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisInfo:
    status: str
    started_at_utc: str
    finished_at_utc: str
    duration_ms: int
    scanners: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    engine_version: str | None = None
    plan_sha256: str | None = None
    search_plan_schema_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # Drop null optional plan fields for compact reports without a plan
        if payload.get("plan_sha256") is None:
            payload.pop("plan_sha256", None)
        if payload.get("search_plan_schema_version") is None:
            payload.pop("search_plan_schema_version", None)
        if payload.get("engine_version") is None:
            payload.pop("engine_version", None)
        return payload


@dataclass
class Report:
    schema_version: str
    report_id: str
    generated_at_utc: str
    tool: ToolInfo
    input: InputInfo
    artifact: ArtifactInfo
    analysis: AnalysisInfo
    manifest: dict[str, Any] = field(default_factory=dict)
    zip_inventory: dict[str, Any] = field(default_factory=dict)
    dex_inventory: list[dict[str, Any]] = field(default_factory=list)
    native_inventory: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    profile_matches: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    dex_context: dict[str, Any] | None = None
    bluetooth_path: dict[str, Any] | None = None
    bluetooth_dataflow: dict[str, Any] | None = None
    artifact_bundle: dict[str, Any] | None = None
    search_plan: dict[str, Any] | None = None
    analysis_job: dict[str, Any] | None = None
    resource: dict[str, Any] | None = None
    raw: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "report_id": self.report_id,
            "generated_at_utc": self.generated_at_utc,
            "tool": self.tool.to_dict(),
            "input": self.input.to_dict(),
            "artifact": self.artifact.to_dict(),
            "analysis": self.analysis.to_dict(),
            "manifest": self.manifest,
            "zip_inventory": self.zip_inventory,
            "dex_inventory": self.dex_inventory,
            "native_inventory": self.native_inventory,
            "findings": [f.to_dict() for f in self.findings],
            "profile_matches": self.profile_matches,
            "limitations": self.limitations,
        }
        if self.dex_context is not None:
            payload["dex_context"] = self.dex_context
        if self.bluetooth_path is not None:
            payload["bluetooth_path"] = self.bluetooth_path
        if self.bluetooth_dataflow is not None:
            payload["bluetooth_dataflow"] = self.bluetooth_dataflow
        if self.artifact_bundle is not None:
            payload["artifact_bundle"] = self.artifact_bundle
        if self.search_plan is not None:
            payload["search_plan"] = self.search_plan
        if self.analysis_job is not None:
            payload["analysis_job"] = self.analysis_job
        if self.resource is not None:
            payload["resource"] = self.resource
        if self.raw is not None:
            payload["raw"] = self.raw
        return payload

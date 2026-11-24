"""Default configuration for apk-forensics."""

from __future__ import annotations

from dataclasses import dataclass

MIN_STRING_LENGTH = 4
MAX_CONTEXT_LENGTH = 160
MAX_FINDINGS_PER_SCANNER = 10000
MAX_PROFILE_REGEX_MATCHES = 5000
HASH_CHUNK_SIZE = 1024 * 1024
MAX_ENTRY_READ_BYTES = 64 * 1024 * 1024
MAX_STRING_VALUE_LENGTH = 512
HIGH_ENTROPY_MIN_LENGTH = 40
DEFAULT_INSTRUCTION_WINDOW = 8
DEFAULT_XREF_DEPTH = 0
DEFAULT_MAX_DEX_CONTEXT_RESULTS = 100
DEFAULT_MAX_CALLERS = 20
DEFAULT_MAX_CALLEES = 20


@dataclass
class AnalysisConfig:
    """Runtime analysis configuration."""

    min_string_length: int = MIN_STRING_LENGTH
    max_context_length: int = MAX_CONTEXT_LENGTH
    max_findings_per_scanner: int = MAX_FINDINGS_PER_SCANNER
    max_profile_regex_matches: int = MAX_PROFILE_REGEX_MATCHES
    hash_chunk_size: int = HASH_CHUNK_SIZE
    max_entry_read_bytes: int = MAX_ENTRY_READ_BYTES
    include_raw: bool = False
    debug: bool = False
    fail_on_error: bool = False
    formats: tuple[str, ...] = ("json", "markdown")
    # v0.2 DEX context
    dex_context: bool = False
    instruction_window: int = DEFAULT_INSTRUCTION_WINDOW
    xref_depth: int = DEFAULT_XREF_DEPTH
    max_dex_context_results: int = DEFAULT_MAX_DEX_CONTEXT_RESULTS
    max_callers: int = DEFAULT_MAX_CALLERS
    max_callees: int = DEFAULT_MAX_CALLEES
    dex_finding_id: str | None = None
    dex_query: str | None = None
    dex_category: str | None = None
    dex_kind: str | None = None
    include_unmatched: bool = False
    # v0.3 Bluetooth RFCOMM path
    bluetooth_path: bool = False
    bluetooth_target: str | None = None
    bluetooth_window: int = 12
    bluetooth_dataflow_depth: int = 2
    bluetooth_max_paths: int = 50
    bluetooth_max_results: int = 100
    # v0.4 storage / cache
    keep_work: bool = False
    use_cache: bool = False
    copy_input: bool = False

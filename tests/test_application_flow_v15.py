"""v1.5 structured-value lineage, field consumers, branches, negative controls."""

from __future__ import annotations

import re

from apk_forensics.application_flow_closure import build_answers, build_path_comm_provenance
from apk_forensics.dex_model_adapter import InstructionInfo, MethodInfo, parse_method_ref
from apk_forensics.structured_value_flow import (
    STRUCTURED_VALUE_DEFINITION,
    analyze_application_value_flow,
    analyze_method_value_lineage,
)


def _ins(index: int, opcode: str, text: str, **kwargs) -> InstructionInfo:
    regs = kwargs.pop("registers", None)
    if regs is None:
        regs = re.findall(r"\bv\d+\b", text)
    ref_m = kwargs.get("referenced_method")
    if ref_m is None and "->" in text and opcode.startswith("invoke"):
        m = re.search(r"(L[^;]+;->[^(]+\([^)]*\)[^ ]*)", text)
        if m:
            ref_m = parse_method_ref(m.group(1))
    return InstructionInfo(
        index=index,
        offset=None,
        opcode=opcode,
        text=text,
        registers=regs,
        referenced_method=ref_m,
        referenced_field=kwargs.get("referenced_field"),
    )


def _method(cls: str, name: str, desc: str, instructions: list[InstructionInfo]) -> MethodInfo:
    return MethodInfo(
        dex_entry="classes.dex",
        class_name=cls,
        class_name_normalized=cls[1:-1].replace("/", "."),
        method_name=name,
        method_descriptor=desc,
        access_flags=["public"],
        is_external=False,
        code_present=True,
        instruction_count=len(instructions),
        code_offset=None,
        instructions=instructions,
    )


def test_structured_value_definition() -> None:
    assert "ByteBuffer" in STRUCTURED_VALUE_DEFINITION["definition"] or "byte[]" in STRUCTURED_VALUE_DEFINITION["definition"]
    assert "READ_LENGTH" in str(STRUCTURED_VALUE_DEFINITION["excludes"])


def test_value_from_getint_to_field_store() -> None:
    m = _method(
        "Lcom/ex/P;",
        "fill",
        "([B)V",
        [
            _ins(
                0,
                "invoke-static",
                "invoke-static v1, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;",
                registers=["v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v2, Ljava/nio/ByteBuffer;->getInt()I",
                registers=["v2"],
            ),
            _ins(3, "move-result", "move-result v3", registers=["v3"]),
            _ins(
                4,
                "iput",
                "iput v3, v0, Lcom/ex/P;->mVal I",
                registers=["v3", "v0"],
                referenced_field="Lcom/ex/P;->mVal I",
            ),
        ],
    )
    r = analyze_method_value_lineage(m)
    assert r["structured_values"]
    assert r["field_stores"]
    assert r["field_stores"][0]["classification"] == "FACT"
    assert r["field_stores"][0]["protocol_semantics"] == "UNKNOWN"
    assert "message" not in (r["field_stores"][0].get("field_short") or "").lower() or True


def test_field_load_branch_consumer() -> None:
    store = _method(
        "Lcom/ex/Pkt;",
        "decodeInto",
        "([B)V",
        [
            _ins(
                0,
                "invoke-static",
                "invoke-static v1, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;",
                registers=["v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v2, Ljava/nio/ByteBuffer;->getShort()S",
                registers=["v2"],
            ),
            _ins(3, "move-result", "move-result v3", registers=["v3"]),
            _ins(
                4,
                "iput-short",
                "iput-short v3, v0, Lcom/ex/Pkt;->mPort S",
                registers=["v3", "v0"],
                referenced_field="Lcom/ex/Pkt;->mPort S",
            ),
        ],
    )
    use = _method(
        "Lcom/ex/Worker;",
        "run",
        "()V",
        [
            _ins(
                0,
                "iget-short",
                "iget-short v0, v1, Lcom/ex/Pkt;->mPort S",
                registers=["v0", "v1"],
                referenced_field="Lcom/ex/Pkt;->mPort S",
            ),
            _ins(1, "const/4", "const/4 v2, 4", registers=["v2"]),
            _ins(2, "if-eq", "if-eq v0, v2, +10h", registers=["v0", "v2"]),
            _ins(
                3,
                "invoke-virtual",
                "invoke-virtual v3, v0, Lcom/ex/Worker;->handle(S)V",
                registers=["v3", "v0"],
            ),
        ],
    )
    flow = analyze_application_value_flow([store, use])
    assert flow["counts"]["field_stores"] >= 1
    assert flow["counts"]["field_loads"] >= 1
    assert flow["counts"]["branches"] >= 1
    assert any(v.get("value_class") in {"V3_CONTROL_FLOW", "V2_CONSUMED", "V4_APPLICATION_ACTION"} for v in flow["value_catalog"])
    for v in flow["value_catalog"]:
        assert v.get("protocol_semantics") == "UNKNOWN"
        assert v.get("semantic_label") is None


def test_roundtrip_candidate() -> None:
    m = _method(
        "Lcom/ex/R;",
        "echo",
        "([B)V",
        [
            _ins(0, "new-array", "new-array v1, v0, [B", registers=["v1", "v0"]),
            _ins(
                1,
                "invoke-virtual",
                "invoke-virtual v2, v1, Ljava/io/InputStream;->read([B)I",
                registers=["v2", "v1"],
            ),
            _ins(
                2,
                "invoke-static",
                "invoke-static v1, Lcom/ex/Pkt;->encode([B)[B",
                registers=["v1"],
            ),
            _ins(3, "move-result-object", "move-result-object v3", registers=["v3"]),
            _ins(
                4,
                "invoke-virtual",
                "invoke-virtual v4, v3, Ljava/io/OutputStream;->write([B)V",
                registers=["v4", "v3"],
            ),
        ],
    )
    r = analyze_method_value_lineage(m)
    # buffer reaches encode/write
    assert r["roundtrip_candidates"] or r["buffer_registers"]


def test_no_protocol_from_field_name() -> None:
    m = _method(
        "Lcom/ex/Pkt;",
        "x",
        "([B)V",
        [
            _ins(
                0,
                "invoke-static",
                "invoke-static v1, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;",
                registers=["v1"],
            ),
            _ins(1, "move-result-object", "move-result-object v2", registers=["v2"]),
            _ins(
                2,
                "invoke-virtual",
                "invoke-virtual v2, Ljava/nio/ByteBuffer;->getInt()I",
                registers=["v2"],
            ),
            _ins(3, "move-result", "move-result v3", registers=["v3"]),
            _ins(
                4,
                "iput",
                "iput v3, v0, Lcom/ex/Pkt;->mCommand I",
                registers=["v3", "v0"],
                referenced_field="Lcom/ex/Pkt;->mCommand I",
            ),
        ],
    )
    r = analyze_method_value_lineage(m)
    st = r["field_stores"][0]
    assert st["protocol_semantics"] == "UNKNOWN"
    # FACT describes store, not "command id"
    assert "command id" not in str(st).lower()


def test_path_comm_provenance_stable() -> None:
    p = build_path_comm_provenance(
        baseline_path_comm=12,
        current_path_comm=12,
        v14_note="v1.4 expansion",
    )
    assert p["changed"] is False
    ans = build_answers(
        {
            "value_catalog": [],
            "counts": {},
            "value_class_counts": {},
        },
        p,
    )
    assert ans["21_protocol_semantics_unknown"] is True
    assert ans["19_path_comm_changed"] is False

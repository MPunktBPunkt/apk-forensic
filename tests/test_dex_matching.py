from __future__ import annotations

from apk_forensics.dex_matcher import MatchQuery, find_dex_matches, prioritize_value
from apk_forensics.dex_model_adapter import DexSession, InstructionInfo, MethodInfo


def _method_with_insns(name: str, texts: list[tuple[str, str]]) -> MethodInfo:
    instructions = []
    for idx, (opcode, text) in enumerate(texts):
        ref_method = None
        ref_string = None
        if opcode.startswith("invoke") and "->" in text:
            from apk_forensics.dex_model_adapter import parse_method_ref

            m = text.split(" ", 1)[-1]
            # text like: invoke-virtual v0, Lcom/...;->foo()V
            import re

            mm = re.search(r"(L[^;]+;->[^(]+\([^)]*\)[^ ]*)", text)
            if mm:
                ref_method = parse_method_ref(mm.group(1))
        if opcode.startswith("const-string"):
            ref_string = text.split(",", 1)[-1].strip().strip('"')
        instructions.append(
            InstructionInfo(
                index=idx,
                offset=None,
                opcode=opcode,
                text=f"{opcode} {text}".strip() if not text.startswith(opcode) else text,
                referenced_method=ref_method,
                referenced_string=ref_string,
            )
        )
    return MethodInfo(
        dex_entry="classes.dex",
        class_name="Lcom/example/BluetoothTransport;",
        class_name_normalized="com.example.BluetoothTransport",
        method_name=name,
        method_descriptor="()V",
        access_flags=["public"],
        is_external=False,
        code_present=True,
        instruction_count=len(instructions),
        code_offset=None,
        instructions=instructions,
    )


def test_method_reference_vs_string() -> None:
    connect = _method_with_insns(
        "connect",
        [
            (
                "invoke-virtual",
                "invoke-virtual v0, v1, Landroid/bluetooth/BluetoothDevice;->createRfcommSocketToServiceRecord(Ljava/util/UUID;)Landroid/bluetooth/BluetoothSocket;",
            ),
            (
                "const-string",
                'const-string v2, "00001101-0000-1000-8000-00805F9B34FB"',
            ),
        ],
    )
    unrelated = _method_with_insns(
        "unrelatedMethod",
        [("const-string", 'const-string v0, "BCL"')],
    )
    session = DexSession(units=[], methods=[connect, unrelated], parser_version="test")
    matches = find_dex_matches(
        session,
        [
            MatchQuery(value="createRfcommSocketToServiceRecord", kind="api"),
            MatchQuery(value="BCL", kind="profile_match"),
            MatchQuery(value="00001101-0000-1000-8000-00805F9B34FB", kind="uuid"),
        ],
        max_results=20,
    )
    by_value = {m.matched_value: m for m in matches}
    assert by_value["createRfcommSocketToServiceRecord"].match_type == "method_reference"
    assert by_value["createRfcommSocketToServiceRecord"].method.method_name == "connect"
    assert by_value["BCL"].match_type == "string"
    assert by_value["BCL"].method.method_name == "unrelatedMethod"
    assert by_value["00001101-0000-1000-8000-00805F9B34FB"].method.method_name == "connect"
    # different methods not collapsed
    assert by_value["createRfcommSocketToServiceRecord"].method.method_name != by_value["BCL"].method.method_name


def test_priority_high_for_rfcomm() -> None:
    priority, score, reasons = prioritize_value(
        "createRfcommSocketToServiceRecord",
        kind="api",
        instruction_text="invoke-virtual ...createRfcommSocketToServiceRecord...",
    )
    assert priority == "high"
    assert score >= 90
    assert reasons

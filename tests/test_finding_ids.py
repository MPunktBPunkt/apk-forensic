from __future__ import annotations

from apk_forensics.finding_factory import make_finding, sort_and_assign_display_ids


def test_stable_id_same_input() -> None:
    a = make_finding(
        artifact_sha256="sha",
        kind="api",
        category="bluetooth",
        value="createRfcommSocketToServiceRecord",
        source_entry="classes.dex",
        offset=100,
        scanner="api_scanner",
    )
    b = make_finding(
        artifact_sha256="sha",
        kind="api",
        category="bluetooth",
        value="createRfcommSocketToServiceRecord",
        source_entry="classes.dex",
        offset=100,
        scanner="api_scanner",
    )
    assert a.id == b.id


def test_different_source_different_id() -> None:
    a = make_finding(
        artifact_sha256="sha",
        kind="api",
        category="bluetooth",
        value="createRfcommSocketToServiceRecord",
        source_entry="classes.dex",
        offset=100,
        scanner="api_scanner",
    )
    b = make_finding(
        artifact_sha256="sha",
        kind="api",
        category="bluetooth",
        value="createRfcommSocketToServiceRecord",
        source_entry="classes2.dex",
        offset=100,
        scanner="api_scanner",
    )
    assert a.id != b.id


def test_order_does_not_change_stable_id() -> None:
    f1 = make_finding(
        artifact_sha256="sha",
        kind="uuid",
        category="bluetooth",
        value="00001101-0000-1000-8000-00805f9b34fb",
        source_entry="classes.dex",
        offset=10,
        scanner="uuid_scanner",
    )
    f2 = make_finding(
        artifact_sha256="sha",
        kind="api",
        category="bluetooth",
        value="fetchUuidsWithSdp",
        source_entry="classes.dex",
        offset=5,
        scanner="api_scanner",
    )
    ordered = sort_and_assign_display_ids([f1, f2])
    reordered = sort_and_assign_display_ids([f2, f1])
    assert {f.id for f in ordered} == {f.id for f in reordered}
    assert [f.display_id for f in ordered] == [f.display_id for f in reordered]

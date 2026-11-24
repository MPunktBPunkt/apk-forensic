"""Command-line interface for apk-forensics."""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from apk_forensics import __version__
from apk_forensics.analysis_job import (
    JobCancelled,
    JobLimitExceeded,
    JobRuntimeLimit,
    create_analysis_job,
    format_preflight_text,
    enrich_actual_from_report,
    mark_completed,
    mark_failed,
    mark_running,
    preflight_or_reject,
)
from apk_forensics.artifact_bundle import load_paths_from_bundle_arg
from apk_forensics.bundle_pipeline import run_bundle_pipeline
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ApkForensicsError, ExitCode, InputError, InvalidApkError
from apk_forensics.logging_config import configure_logging
from apk_forensics.pipeline import run_pipeline
from apk_forensics.resource_guard import ResourceRejectedError, ResourceWarningBlockedError
from apk_forensics.resource_policy import DEFAULT_POLICY_NAME, get_resource_policy
from apk_forensics.search_plan import (
    PlanValidationError,
    apply_search_plan_to_config,
    format_plan_valid_summary,
    load_search_plan,
    resolve_profile_from_plan,
)
from apk_forensics.storage import collect_storage_report, execute_cleanup, parse_older_than, plan_cleanup
from apk_forensics.workspace import create_work_session, discover_workspace


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apk-forensics",
        description="Static APK forensics toolkit (local, no execution, no network).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan an APK (or ArtifactBundle) and write forensic reports.")
    scan.add_argument(
        "apk_path",
        type=Path,
        nargs="?",
        default=None,
        help="Path to a single APK file (omit when using --bundle)",
    )
    scan.add_argument("--output", type=Path, required=True, help="Output directory")
    scan.add_argument(
        "--bundle",
        default=None,
        help="Directory of related APKs, or use with --split for explicit members",
    )
    scan.add_argument(
        "--split",
        action="append",
        default=None,
        dest="splits",
        help="Additional split APK path (repeatable); used with apk_path as base",
    )
    scan.add_argument(
        "--plan",
        type=Path,
        default=None,
        help="Path to a declarative SearchPlan YAML (validated + normalized before scan)",
    )
    scan.add_argument(
        "--profile",
        default=None,
        help="Profile path or name (e.g. bmw_connected or ./profiles/bmw_connected.yaml)",
    )
    scan.add_argument(
        "--format",
        dest="formats",
        action="append",
        choices=["json", "markdown", "all"],
        default=None,
        help="Output format (repeatable). Default: json and markdown.",
    )
    scan.add_argument("--include-raw", action="store_true", help="Include raw debug section in JSON")
    scan.add_argument("--debug", action="store_true", help="Verbose logging and include REJECTED findings")
    scan.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Treat fatal scanner errors as exit code 5",
    )
    scan.add_argument("--min-string-length", type=int, default=None)
    scan.add_argument("--max-context-length", type=int, default=None)
    scan.add_argument(
        "--keep-work",
        action="store_true",
        help="Keep temporary work session data after scan (default: delete)",
    )
    scan.add_argument(
        "--copy-input",
        action="store_true",
        help="Explicitly request copying inputs into managed source (default: analyze in place)",
    )
    scan.add_argument(
        "--use-cache",
        action="store_true",
        help="Enable optional bounded analysis cache (default: off)",
    )
    scan.add_argument(
        "--resource-policy",
        default=DEFAULT_POLICY_NAME,
        choices=["conservative", "standard", "unlimited"],
        help="Resource policy for preflight/runtime budgets (default: standard)",
    )
    scan.add_argument(
        "--allow-resource-warning",
        action="store_true",
        help="Proceed when Resource Guard returns WARNING (REJECT cannot be overridden)",
    )

    # v0.2 DEX context options
    scan.add_argument(
        "--dex-context",
        action="store_true",
        help="Enable optional DEX context / bounded XREF analysis (requires androguard)",
    )
    scan.add_argument("--finding-id", default=None, help="Limit DEX context to one finding id/display id")
    scan.add_argument("--query", default=None, help="Limit DEX context to values containing this query")
    scan.add_argument("--category", default=None, help="Limit DEX context by finding category")
    scan.add_argument("--kind", default=None, help="Limit DEX context by finding kind")
    scan.add_argument("--max-results", type=int, default=100, help="Max DEX context results (default 100)")
    scan.add_argument(
        "--instruction-window",
        type=int,
        default=8,
        help="Instruction window before/after match (0-100, default 8)",
    )
    scan.add_argument(
        "--xref-depth",
        type=int,
        default=0,
        help="Bounded XREF depth (0-2, default 0)",
    )
    scan.add_argument("--max-callers", type=int, default=20)
    scan.add_argument("--max-callees", type=int, default=20)
    scan.add_argument(
        "--include-unmatched",
        action="store_true",
        help="Keep broader query selection even when filters are narrow",
    )

    # v0.3 Bluetooth RFCOMM path options
    scan.add_argument(
        "--bluetooth-path",
        action="store_true",
        help="Enable Bluetooth RFCOMM path / UUID / socket analysis (requires androguard)",
    )
    scan.add_argument(
        "--bluetooth-target",
        default=None,
        help="Limit Bluetooth path analysis to class/method/API containing this query",
    )
    scan.add_argument("--bluetooth-max-results", type=int, default=100)
    scan.add_argument("--bluetooth-window", type=int, default=12)
    scan.add_argument("--bluetooth-dataflow-depth", type=int, default=2)
    scan.add_argument("--bluetooth-max-paths", type=int, default=50)
    scan.add_argument("--bluetooth-caller-depth", type=int, default=2)
    scan.add_argument(
        "--no-bluetooth-callers",
        action="store_true",
        help="Disable RFCOMM caller reconstruction",
    )
    scan.add_argument(
        "--no-bluetooth-streams",
        action="store_true",
        help="Disable socket/stream reconstruction",
    )
    scan.add_argument(
        "--no-bluetooth-read-write",
        action="store_true",
        help="Disable InputStream/OutputStream read-write reconstruction",
    )
    scan.add_argument("--bluetooth-max-callers", type=int, default=50)
    scan.add_argument("--bluetooth-max-dataflow-paths", type=int, default=50)
    scan.add_argument("--bluetooth-max-dataflow-nodes", type=int, default=200)
    scan.add_argument(
        "--bluetooth-interprocedural",
        action="store_true",
        help="Enable bounded cross-method socket/stream object-flow (v0.8)",
    )
    scan.add_argument("--bluetooth-max-method-hops", type=int, default=3)
    scan.add_argument("--bluetooth-max-field-hops", type=int, default=2)
    scan.add_argument("--bluetooth-max-object-nodes", type=int, default=500)
    scan.add_argument(
        "--communication",
        action="store_true",
        help="Enable v1.0 communication evidence (bytes/buffer/parser/message) above transport",
    )

    post = sub.add_parser(
        "postprocess-communication",
        help="Offline v1.0 communication analysis on a persisted transport report (prefer over full re-scan).",
    )
    post.add_argument("--from-report", type=Path, required=True, help="Existing report.json with bluetooth_path")
    post.add_argument("--apk", type=Path, required=True, help="APK providing method bodies")
    post.add_argument("--output", type=Path, required=True, help="Output directory for enhanced report")
    post.add_argument(
        "--plan",
        type=Path,
        default=None,
        help="Optional SearchPlan (uses communication: section; default: plans/communication_evidence.yaml)",
    )

    storage_cmd = sub.add_parser("storage", help="Show managed workspace storage usage.")
    storage_cmd.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Workspace root (default: discover from CWD)",
    )
    storage_cmd.add_argument("--json", action="store_true", help="Emit JSON instead of text table")

    clean = sub.add_parser("clean", help="Safely clean managed work/cache/output areas.")
    clean.add_argument("--workspace", type=Path, default=None, help="Workspace root")
    clean.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Show what would be removed without deleting (default)",
    )
    clean.add_argument(
        "--execute",
        action="store_true",
        help="Actually delete planned paths (disables dry-run)",
    )
    clean.add_argument("--work", action="store_true", help="Include work/ (default if no area flag)")
    clean.add_argument("--cache", action="store_true", help="Include cache/")
    clean.add_argument("--output", action="store_true", help="Include output/ reports (opt-in)")
    clean.add_argument(
        "--older-than",
        default=None,
        help="Only remove items older than duration (e.g. 30d, 12h)",
    )
    clean.add_argument(
        "--protect-output",
        action="append",
        default=None,
        help="Output subdirectory name to protect (repeatable)",
    )

    plan_cmd = sub.add_parser("plan", help="Validate / show / estimate declarative SearchPlans.")
    plan_sub = plan_cmd.add_subparsers(dest="plan_command", required=True)
    plan_validate = plan_sub.add_parser("validate", help="Validate a SearchPlan without scanning.")
    plan_validate.add_argument("plan_path", type=Path, help="Path to SearchPlan YAML")
    plan_show = plan_sub.add_parser("show", help="Show normalized SearchPlan + plan_sha256.")
    plan_show.add_argument("plan_path", type=Path, help="Path to SearchPlan YAML")
    plan_show.add_argument("--json", action="store_true", help="Emit canonical JSON")
    plan_estimate = plan_sub.add_parser(
        "estimate",
        help="Preflight resource estimate for APK(s) + SearchPlan (no deep analysis).",
    )
    plan_estimate.add_argument("apk_path", type=Path, help="Path to APK")
    plan_estimate.add_argument("--plan", type=Path, required=True, help="SearchPlan YAML")
    plan_estimate.add_argument(
        "--split",
        action="append",
        default=None,
        dest="splits",
        help="Additional split APK (repeatable)",
    )
    plan_estimate.add_argument(
        "--resource-policy",
        default=DEFAULT_POLICY_NAME,
        choices=["conservative", "standard", "unlimited"],
    )
    plan_estimate.add_argument("--json", action="store_true", help="Emit JSON")

    field_cmd = sub.add_parser(
        "diagnose-field-coverage",
        help="v1.2 field/alias coverage report from a persisted transport report (diagnostic).",
    )
    field_cmd.add_argument(
        "--from-report",
        type=Path,
        required=True,
        help="report.json with bluetooth evidence paths (e.g. bmw-connected-600-v10)",
    )
    field_cmd.add_argument("--output", type=Path, required=True, help="Output directory")

    closure_cmd = sub.add_parser(
        "diagnose-transport-closure",
        help="v1.3 transport-to-byte evidence closure from a persisted report (offline).",
    )
    closure_cmd.add_argument(
        "--from-report",
        type=Path,
        required=True,
        help="report.json with bluetooth + communication evidence",
    )
    closure_cmd.add_argument("--output", type=Path, required=True, help="Output directory")
    closure_cmd.add_argument(
        "--baseline-meta",
        type=Path,
        default=None,
        help="Optional BASELINE_META.json from a frozen v1.2 snapshot",
    )

    sem_cmd = sub.add_parser(
        "diagnose-buffer-semantics",
        help="v1.4 buffer-to-semantics closure (T5 audit + optional interface-consumer expansion).",
    )
    sem_cmd.add_argument("--from-report", type=Path, required=True, help="Persisted report.json")
    sem_cmd.add_argument("--output", type=Path, required=True, help="Output directory")
    sem_cmd.add_argument(
        "--apk",
        type=Path,
        default=None,
        help="APK for expanded communication re-analysis (interface consumers)",
    )
    sem_cmd.add_argument(
        "--v13-closure",
        type=Path,
        default=None,
        help="Optional TRANSPORT_EVIDENCE_CLOSURE_REPORT.json from v1.3",
    )
    sem_cmd.add_argument(
        "--baseline-meta",
        type=Path,
        default=None,
        help="Optional frozen baseline meta JSON",
    )
    sem_cmd.add_argument(
        "--expand-interface-consumers",
        action="store_true",
        help="Widen method seeds to AccessorySocket/Packet buffer consumers (documented gap fix)",
    )

    calibrate_cmd = sub.add_parser(
        "calibrate",
        help="v1.1 resource estimate audit + coverage reports from persisted runs (no APK execution).",
    )
    calibrate_cmd.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory for RESOURCE_ESTIMATE_REPORT and COVERAGE_REPORT",
    )
    calibrate_cmd.add_argument(
        "--focus-report",
        type=Path,
        default=None,
        help="Primary report.json (default: output/bmw-connected-600-v10/report.json if present)",
    )
    calibrate_cmd.add_argument(
        "--apk",
        type=Path,
        default=None,
        help="APK for estimate-only sensitivity sweeps (optional)",
    )
    calibrate_cmd.add_argument(
        "--plan",
        type=Path,
        default=None,
        help="SearchPlan for sensitivity (default: plans/communication_evidence.yaml)",
    )
    calibrate_cmd.add_argument(
        "--history",
        type=Path,
        nargs="*",
        default=None,
        help="Additional historical report.json paths (defaults to known output/*/report.json)",
    )

    # Alias: apk-forensics estimate ...
    estimate_cmd = sub.add_parser(
        "estimate",
        help="Alias for 'plan estimate' — preflight resource estimate (no deep analysis).",
    )
    estimate_cmd.add_argument("apk_path", type=Path, help="Path to APK")
    estimate_cmd.add_argument("--plan", type=Path, required=True, help="SearchPlan YAML")
    estimate_cmd.add_argument(
        "--split",
        action="append",
        default=None,
        dest="splits",
        help="Additional split APK (repeatable)",
    )
    estimate_cmd.add_argument(
        "--resource-policy",
        default=DEFAULT_POLICY_NAME,
        choices=["conservative", "standard", "unlimited"],
    )
    estimate_cmd.add_argument("--json", action="store_true", help="Emit JSON")
    return parser


def _resolve_formats(values: list[str] | None) -> tuple[str, ...]:
    if not values:
        return ("json", "markdown")
    if "all" in values:
        return ("json", "markdown")
    out: list[str] = []
    for item in values:
        if item not in out:
            out.append(item)
    return tuple(out)


def _validate_scan_args(args: argparse.Namespace) -> int | None:
    if args.instruction_window < 0 or args.instruction_window > 100:
        print("error: --instruction-window must be between 0 and 100", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.xref_depth < 0 or args.xref_depth > 2:
        print("error: --xref-depth must be between 0 and 2", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.max_results < 1:
        print("error: --max-results must be >= 1", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.bluetooth_window < 0 or args.bluetooth_window > 100:
        print("error: --bluetooth-window must be between 0 and 100", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.bluetooth_dataflow_depth < 0 or args.bluetooth_dataflow_depth > 3:
        print("error: --bluetooth-dataflow-depth must be between 0 and 3", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.bluetooth_max_paths < 1 or args.bluetooth_max_paths > 500:
        print("error: --bluetooth-max-paths must be between 1 and 500", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.bluetooth_max_results < 1 or args.bluetooth_max_results > 500:
        print("error: --bluetooth-max-results must be between 1 and 500", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.bluetooth_caller_depth < 0 or args.bluetooth_caller_depth > 2:
        print("error: --bluetooth-caller-depth must be between 0 and 2", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.bluetooth_max_callers < 0 or args.bluetooth_max_callers > 100:
        print("error: --bluetooth-max-callers must be between 0 and 100", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.bluetooth_max_dataflow_paths < 0 or args.bluetooth_max_dataflow_paths > 100:
        print("error: --bluetooth-max-dataflow-paths must be between 0 and 100", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.bluetooth_max_dataflow_nodes < 0 or args.bluetooth_max_dataflow_nodes > 500:
        print("error: --bluetooth-max-dataflow-nodes must be between 0 and 500", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    if args.apk_path is None and not args.bundle and not args.splits:
        print("error: provide apk_path and/or --bundle / --split", file=sys.stderr)
        return ExitCode.INVALID_ARGS
    return None


def _cmd_storage(args: argparse.Namespace) -> int:
    ws = discover_workspace(args.workspace)
    ws.ensure()
    report = collect_storage_report(ws)
    if args.json:
        import json

        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_text(), end="")
    return ExitCode.SUCCESS


def _cmd_clean(args: argparse.Namespace) -> int:
    ws = discover_workspace(args.workspace)
    ws.ensure()
    # Default areas: work + cache unless user selected specific flags
    any_area = bool(args.work or args.cache or args.output)
    clean_work = args.work or not any_area
    clean_cache = args.cache or not any_area
    clean_output = bool(args.output)

    older = None
    if args.older_than:
        try:
            older = parse_older_than(args.older_than)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return ExitCode.INVALID_ARGS

    protect = set(args.protect_output or [])
    plan = plan_cleanup(
        ws,
        clean_work=clean_work,
        clean_cache=clean_cache,
        clean_output=clean_output,
        older_than=older,
        protect_output_names=protect,
    )
    dry_run = not bool(args.execute)
    plan = execute_cleanup(ws, plan, dry_run=dry_run)
    prefix = "Would remove" if dry_run else "Removed"
    # reuse text but adjust header for execute
    text = plan.to_text()
    if not dry_run:
        text = text.replace("Would remove:", f"{prefix}:", 1).replace("Would keep:", "Kept:", 1)
    print(text, end="")
    if plan.errors:
        return ExitCode.PARTIAL_OR_WARNINGS
    return ExitCode.SUCCESS


def _cmd_plan(args: argparse.Namespace) -> int:
    import json

    if args.plan_command == "estimate":
        return _cmd_estimate(args)

    try:
        plan = load_search_plan(args.plan_path)
    except PlanValidationError as exc:
        print(str(exc), file=sys.stderr)
        return ExitCode.INVALID_ARGS

    if args.plan_command == "validate":
        print(format_plan_valid_summary(plan), end="")
        return ExitCode.SUCCESS

    if args.plan_command == "show":
        payload = plan.to_report_section()
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(format_plan_valid_summary(plan), end="")
            print()
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        return ExitCode.SUCCESS

    return ExitCode.INVALID_ARGS


def _cmd_estimate(args: argparse.Namespace) -> int:
    import json

    try:
        plan = load_search_plan(args.plan)
    except PlanValidationError as exc:
        print(str(exc), file=sys.stderr)
        return ExitCode.INVALID_ARGS

    paths = [args.apk_path.resolve()]
    for s in args.splits or []:
        paths.append(Path(s).resolve())
    for p in paths:
        if not p.is_file():
            print(f"error: input not found: {p}", file=sys.stderr)
            return ExitCode.INPUT_UNREADABLE

    try:
        policy = get_resource_policy(args.resource_policy)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ExitCode.INVALID_ARGS

    try:
        job, fingerprints, factors = create_analysis_job(
            apk_paths=paths,
            search_plan=plan,
            policy=policy,
        )
    except InvalidApkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ExitCode.INVALID_APK
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return ExitCode.FATAL

    assert job.resource_decision is not None and job.resource_estimate is not None
    if args.json:
        payload = {
            "plan_sha256": plan.plan_sha256,
            "plan_name": plan.plan_name,
            "job_id": job.job_id,
            "artifacts": [f.to_dict() for f in fingerprints],
            "factors": factors.to_dict(),
            "estimate": job.resource_estimate.to_dict(),
            "decision": job.resource_decision.to_dict(),
            "policy": policy.to_dict(),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(
            format_preflight_text(
                plan=plan,
                fingerprints=fingerprints,
                factors=factors,
                estimate=job.resource_estimate,
                decision=job.resource_decision,
            ),
            end="",
        )
    # Estimate never starts analysis; WARNING/REJECT are informational here
    if job.resource_decision.decision == "REJECT":
        return ExitCode.RESOURCE_REJECTED
    if job.resource_decision.decision == "WARNING":
        return ExitCode.RESOURCE_WARNING_BLOCKED
    return ExitCode.SUCCESS


def _cmd_scan(args: argparse.Namespace) -> int:
    err = _validate_scan_args(args)
    if err is not None:
        return err

    configure_logging(debug=bool(args.debug))

    search_plan = None
    if args.plan is not None:
        try:
            search_plan = load_search_plan(args.plan)
        except PlanValidationError as exc:
            print(str(exc), file=sys.stderr)
            return ExitCode.INVALID_ARGS

    formats = _resolve_formats(args.formats)
    config = AnalysisConfig(
        include_raw=bool(args.include_raw),
        debug=bool(args.debug),
        fail_on_error=bool(args.fail_on_error),
        formats=formats,
        dex_context=bool(args.dex_context),
        instruction_window=int(args.instruction_window),
        xref_depth=int(args.xref_depth),
        max_dex_context_results=int(args.max_results),
        max_callers=int(args.max_callers),
        max_callees=int(args.max_callees),
        dex_finding_id=args.finding_id,
        dex_query=args.query,
        dex_category=args.category,
        dex_kind=args.kind,
        include_unmatched=bool(args.include_unmatched),
        bluetooth_path=bool(args.bluetooth_path),
        bluetooth_target=args.bluetooth_target,
        bluetooth_window=int(args.bluetooth_window),
        bluetooth_dataflow_depth=int(args.bluetooth_dataflow_depth),
        bluetooth_max_paths=int(args.bluetooth_max_paths),
        bluetooth_max_results=int(args.bluetooth_max_results),
        bluetooth_caller_depth=int(args.bluetooth_caller_depth),
        bluetooth_reconstruct_callers=not bool(args.no_bluetooth_callers),
        bluetooth_reconstruct_streams=not bool(args.no_bluetooth_streams),
        bluetooth_reconstruct_read_write=not bool(args.no_bluetooth_read_write),
        bluetooth_max_callers=int(args.bluetooth_max_callers),
        bluetooth_max_dataflow_paths=int(args.bluetooth_max_dataflow_paths),
        bluetooth_max_dataflow_nodes=int(args.bluetooth_max_dataflow_nodes),
        bluetooth_interprocedural=bool(getattr(args, "bluetooth_interprocedural", False)),
        bluetooth_max_method_hops=int(getattr(args, "bluetooth_max_method_hops", 3)),
        bluetooth_max_field_hops=int(getattr(args, "bluetooth_max_field_hops", 2)),
        bluetooth_max_object_nodes=int(getattr(args, "bluetooth_max_object_nodes", 500)),
        communication=bool(getattr(args, "communication", False)),
        keep_work=bool(args.keep_work),
        use_cache=bool(args.use_cache),
        copy_input=bool(args.copy_input),
    )
    if args.min_string_length is not None:
        config.min_string_length = args.min_string_length
    if args.max_context_length is not None:
        config.max_context_length = args.max_context_length

    # SearchPlan overlays config; explicit CLI flags for deep analysis still apply if set
    if search_plan is not None:
        apply_search_plan_to_config(search_plan, config)
        # CLI can still force-enable deep modules if user passed flags after plan defaults
        if args.dex_context:
            config.dex_context = True
        if args.bluetooth_path:
            config.bluetooth_path = True
        if getattr(args, "communication", False):
            config.communication = True
            config.bluetooth_path = True
        if args.formats:
            config.formats = formats
        if args.include_raw:
            config.include_raw = True
        if args.query:
            config.dex_query = args.query
    elif getattr(args, "communication", False):
        config.communication = True
        config.bluetooth_path = True

    profile_arg = resolve_profile_from_plan(search_plan, args.profile) if search_plan else args.profile

    # Resolve input set before creating work (rejected jobs leave no work dir)
    paths: list[Path] = []
    try:
        if args.bundle:
            paths.extend(load_paths_from_bundle_arg(args.bundle))
        if args.apk_path is not None:
            paths.append(args.apk_path.resolve())
        if args.splits:
            for s in args.splits:
                paths.append(Path(s).resolve())
        seen: set[str] = set()
        uniq: list[Path] = []
        for p in paths:
            key = str(p.resolve())
            if key not in seen:
                seen.add(key)
                uniq.append(p.resolve())
        paths = uniq
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ExitCode.INPUT_UNREADABLE

    if not paths:
        print("error: provide apk_path and/or --bundle / --split", file=sys.stderr)
        return ExitCode.INVALID_ARGS

    try:
        policy = get_resource_policy(args.resource_policy)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ExitCode.INVALID_ARGS

    try:
        job, _fingerprints, _factors = create_analysis_job(
            apk_paths=paths,
            search_plan=search_plan,
            policy=policy,
            allow_resource_warning=bool(args.allow_resource_warning),
            cli_dex_context=bool(config.dex_context),
            cli_bluetooth=bool(config.bluetooth_path),
        )
        preflight_or_reject(job)
    except ResourceRejectedError as exc:
        print(str(exc), file=sys.stderr)
        return ExitCode.RESOURCE_REJECTED
    except ResourceWarningBlockedError as exc:
        print(str(exc), file=sys.stderr)
        return ExitCode.RESOURCE_WARNING_BLOCKED
    except InvalidApkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ExitCode.INVALID_APK
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return getattr(exc, "exit_code", ExitCode.INPUT_UNREADABLE)
    except Exception as exc:  # noqa: BLE001
        print(f"error: preflight failed: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        return ExitCode.FATAL

    if config.copy_input:
        print(
            "note: --copy-input records intent only; inputs are still analyzed in place "
            "(no automatic durable copy of user originals).",
            file=sys.stderr,
        )

    workspace = discover_workspace()
    workspace.ensure()
    run_name = args.output.name if args.output else "scan"
    work = create_work_session(workspace, run_name=run_name, keep=config.keep_work)

    try:
        mark_running(job)
        if len(paths) > 1 or args.bundle:
            bundle_report, outputs, _warnings = run_bundle_pipeline(
                paths,
                args.output,
                config=config,
                profile_path=profile_arg,
                work_session=work,
                search_plan=search_plan,
                analysis_job=job,
            )
            findings_n = len(bundle_report.get("findings") or [])
            mark_completed(job, findings=findings_n, dex_contexts=None, xrefs=None)
            # Refresh job sections on bundle report and rewrite if present
            bundle_report["analysis_job"] = job.to_dict()
            bundle_report["resource"] = job.resource_report_section()
            if "json" in outputs:
                import json

                outputs["json"].write_text(
                    json.dumps(bundle_report, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
            print(f"APK Forensics {__version__}")
            print(f"Mode: ArtifactBundle ({len(paths)} members)")
            print(f"Job: {job.job_id[:16]}… status={job.status}")
            if job.resource_decision:
                print(
                    f"Resource: {job.resource_decision.decision} "
                    f"(est {job.resource_estimate.memory_mb if job.resource_estimate else '?'} MiB)"
                )
            if search_plan is not None:
                print(f"Plan: {search_plan.plan_name} sha256={search_plan.plan_sha256[:16]}…")
            print(f"Bundle: {(bundle_report.get('artifact_bundle') or {}).get('bundle_id')}")
            print(f"Correlation: {(bundle_report.get('artifact_bundle') or {}).get('correlation_status')}")
            print(f"Status: {(bundle_report.get('analysis') or {}).get('status')}")
            for m in bundle_report.get("members") or []:
                print(
                    f"  - {m.get('role')}: {m.get('file_name')} "
                    f"DEX={m.get('dex_count')} .so={m.get('native_so_count')} "
                    f"sha256={(m.get('sha256') or '')[:12]}…"
                )
            if "json" in outputs:
                print(f"JSON: {outputs['json']}")
            if "markdown" in outputs:
                print(f"Markdown: {outputs['markdown']}")
            if not config.keep_work:
                print("Work: cleaned")
            else:
                print(f"Work kept: {work.path}")
            status = (bundle_report.get("analysis") or {}).get("status")
            if status == "failed":
                return ExitCode.FATAL
            if status == "partial" or _warnings:
                return ExitCode.PARTIAL_OR_WARNINGS
            return ExitCode.SUCCESS

        report, outputs, _warnings = run_pipeline(
            paths[0],
            args.output,
            config=config,
            profile_path=profile_arg,
            copy_input=config.copy_input,
            search_plan=search_plan,
            analysis_job=job,
        )
        dex = report.dex_context or {}
        dex_counts = dex.get("counts") or {}
        mark_completed(
            job,
            findings=len([f for f in report.findings if f.classification != "REJECTED"]),
            dex_contexts=dex_counts.get("contexts"),
            xrefs=dex_counts.get("xref_candidates"),
        )
        enrich_actual_from_report(job, report)
        report.analysis_job = job.to_dict()
        report.resource = job.resource_report_section()
        if "json" in outputs:
            from apk_forensics.report_writer import write_json_report

            write_json_report(report, outputs["json"])
        if "markdown" in outputs:
            from apk_forensics.report_writer import write_markdown_report

            write_markdown_report(report, outputs["markdown"])
        work.cleanup()
    except JobCancelled as exc:
        from apk_forensics.analysis_job import mark_cancelled

        mark_cancelled(job, reason=str(exc) or "cancelled")
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return getattr(exc, "exit_code", ExitCode.PARTIAL_OR_WARNINGS)
    except (JobRuntimeLimit, JobLimitExceeded) as exc:
        reason = getattr(exc, "termination_reason", None) or "runtime_limit"
        mark_failed(job, reason)
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return getattr(exc, "exit_code", ExitCode.FATAL)
    except InvalidApkError as exc:
        mark_failed(job, "invalid_apk")
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return ExitCode.INVALID_APK
    except InputError as exc:
        mark_failed(job, "input_error")
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return getattr(exc, "exit_code", ExitCode.INPUT_UNREADABLE)
    except ApkForensicsError as exc:
        mark_failed(job, "analysis_exception")
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return getattr(exc, "exit_code", ExitCode.FATAL)
    except Exception as exc:  # noqa: BLE001
        mark_failed(job, "unexpected_fatal_error")
        print(f"fatal: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return ExitCode.FATAL

    finding_count = len([f for f in report.findings if f.classification != "REJECTED"])
    warning_count = len(report.analysis.warnings)
    dex = report.dex_context or {}
    dex_counts = dex.get("counts") or {}
    bt = report.bluetooth_path or {}
    bt_counts = bt.get("counts") or {}

    print(f"APK Forensics {__version__}")
    print(f"Input: {report.input.path}")
    print(f"SHA256: {report.input.sha256}")
    print(f"Job: {job.job_id[:16]}… status={job.status}")
    if job.resource_decision and job.resource_estimate:
        print(
            f"Resource: {job.resource_decision.decision} "
            f"est={job.resource_estimate.memory_mb}MiB "
            f"actual_rt={job.resource_actual.runtime_seconds}s "
            f"peak_rss={job.resource_actual.peak_memory_mb}"
        )
    if search_plan is not None:
        print(f"Plan: {search_plan.plan_name} sha256={search_plan.plan_sha256}")
    print(f"Status: {report.analysis.status}")
    if config.dex_context or config.bluetooth_path:
        print(f"Shallow findings: {finding_count}")
    else:
        print(f"Findings: {finding_count}")
    if config.dex_context:
        print(f"DEX contexts: {dex_counts.get('contexts', len(dex.get('contexts') or []))}")
        print(f"XREF candidates: {dex_counts.get('xref_candidates', len(dex.get('xref_candidates') or []))}")
        print(f"Candidate chains: {dex_counts.get('candidate_chains', len(dex.get('candidate_chains') or []))}")
    if config.bluetooth_path:
        print(f"RFCOMM targets: {bt_counts.get('targets', len(bt.get('targets') or []))}")
        print(f"UUID resolutions: {bt_counts.get('uuid_resolutions', len(bt.get('uuid_resolutions') or []))}")
        print(f"Bluetooth paths: {bt_counts.get('paths', len(bt.get('paths') or []))}")
        print(f"RFCOMM callers: {bt_counts.get('caller_paths', len(bt.get('caller_paths') or []))}")
        print(f"Dataflow paths: {bt_counts.get('dataflow_paths', len(bt.get('dataflow_paths') or []))}")
        print(f"Dataflow nodes: {bt_counts.get('dataflow_nodes', 0)}")
        print(f"Socket transfers: {bt_counts.get('socket_transfers', 0)}")
        print(f"Stream transfers: {bt_counts.get('stream_transfers', 0)}")
        print(f"InputStream consumers: {bt_counts.get('input_consumers', 0)}")
        print(f"OutputStream producers: {bt_counts.get('output_producers', 0)}")
        eg = bt.get("evidence_graph") or {}
        if eg.get("enabled"):
            eg_sum = eg.get("summary") or {}
            print(f"Evidence paths: {eg_sum.get('evidence_paths', bt_counts.get('evidence_paths', 0))}")
            print(f"Canonical nodes: {bt_counts.get('canonical_nodes', (eg.get('canonical') or {}).get('nodes', 0))}")
            print(f"Strongest evidence: {eg_sum.get('strongest_path_id')} ({eg_sum.get('strongest_path_kind')})")
            print(
                f"End-to-end: {eg_sum.get('strongest_classification')}/"
                f"{eg_sum.get('strongest_confidence')} "
                f"runtime={eg_sum.get('runtime_execution')} "
                f"protocol={eg_sum.get('protocol_semantics')}"
            )
        ce = report.communication_evidence or {}
        if ce.get("enabled"):
            cs = ce.get("summary") or {}
            print(f"Communication paths: {cs.get('communication_paths', 0)}")
            print(f"Comm strongest: {cs.get('strongest_path_id')} ({cs.get('strongest_classification')})")
            print(
                f"Comm protocol={cs.get('protocol_semantics')} "
                f"runtime={cs.get('runtime_execution')}"
            )
    print(f"Warnings: {warning_count}")
    if "json" in outputs:
        print(f"JSON: {outputs['json']}")
    if "markdown" in outputs:
        print(f"Markdown: {outputs['markdown']}")
    if not config.keep_work:
        print("Work: cleaned")
    else:
        print(f"Work kept: {work.path}")

    if report.analysis.status == "failed" or (config.fail_on_error and report.analysis.errors):
        return ExitCode.FATAL
    if report.analysis.status == "partial" or warning_count > 0:
        return ExitCode.PARTIAL_OR_WARNINGS
    return ExitCode.SUCCESS


def _cmd_diagnose_field_coverage(args: argparse.Namespace) -> int:
    import json
    from apk_forensics.field_coverage import (
        build_field_coverage_report,
        classify_root_cause,
        path_matrix_from_report,
        write_field_coverage_reports,
    )

    report_path = Path(args.from_report).resolve()
    out_dir = Path(args.output).resolve()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    matrix = path_matrix_from_report(report)
    cause = classify_root_cause(matrix)
    payload = build_field_coverage_report(
        baseline_report=report,
        root_cause=cause,
        path_matrix=matrix,
        provenance={
            "source_report": str(report_path),
            "source_engine_version": (report.get("tool") or {}).get("version"),
            "source_plan_sha256": (report.get("analysis") or {}).get("plan_sha256"),
            "source_artifact_sha256": (report.get("input") or {}).get("sha256"),
            "postprocessing_version": __version__,
            "default_max_field_hops_changed": False,
        },
        resource_delta={
            "default_max_field_hops": 2,
            "default_changed": False,
            "note": (
                "Root cause is same-field re-entry / hop accounting, not insufficient depth. "
                "Default max_field_hops stays 2; estimator still scales with bt_max_field_hops."
            ),
        },
    )
    jp, mp = write_field_coverage_reports(out_dir, payload)
    print(f"APK Forensics {__version__} diagnose-field-coverage")
    print(f"Source: {report_path}")
    print(f"Case: {cause.get('case')}")
    print(f"MFH paths: {cause.get('mfh_path_count')}")
    print(f"JSON: {jp}")
    print(f"Markdown: {mp}")
    return ExitCode.SUCCESS


def _cmd_diagnose_transport_closure(args: argparse.Namespace) -> int:
    import json
    from apk_forensics.transport_evidence_closure import (
        build_buffer_dataflow_report,
        build_object_identity_report,
        build_termination_report,
        build_transport_closure_report,
        write_closure_reports,
        _index_communication,
        _index_dataflow,
    )

    report_path = Path(args.from_report).resolve()
    out_dir = Path(args.output).resolve()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    baseline_meta = None
    if args.baseline_meta:
        baseline_meta = json.loads(Path(args.baseline_meta).resolve().read_text(encoding="utf-8"))
    closure = build_transport_closure_report(
        report,
        baseline_meta=baseline_meta,
        provenance={
            "source_report": str(report_path),
            "source_engine_version": (report.get("tool") or {}).get("version"),
            "source_plan_sha256": (report.get("analysis") or {}).get("plan_sha256"),
            "source_artifact_sha256": (report.get("input") or {}).get("sha256"),
            "postprocessing_version": __version__,
            "limits_raised": False,
            "max_field_hops": 2,
        },
    )
    bt = report.get("bluetooth_path") or {}
    df_index = _index_dataflow(bt)
    comm_index = _index_communication(report.get("communication_evidence") or {})
    identity = build_object_identity_report(closure.get("paths") or [], bt)
    identity["provenance"] = closure.get("provenance")
    buffer = build_buffer_dataflow_report(closure.get("paths") or [], df_index, comm_index)
    buffer["provenance"] = closure.get("provenance")
    termination = build_termination_report(closure)
    written = write_closure_reports(out_dir, closure, identity, buffer, termination)
    ans = closure.get("answers") or {}
    print(f"APK Forensics {__version__} diagnose-transport-closure")
    print(f"Source: {report_path}")
    print(f"Transport paths: {(closure.get('summary') or {}).get('transport_paths')}")
    print(f"T2 I/O: {ans.get('1_paths_reaching_read_write')}")
    print(f"T3 Buffer: {ans.get('2_paths_reaching_buffer')}")
    print(f"T4 Consumer/Producer: {ans.get('3_paths_reaching_buffer_consumer_producer')}")
    print(f"T5 Decoder/Encoder: {ans.get('4_paths_reaching_decoder_encoder_candidate')}")
    print(f"Protocol semantics: {ans.get('protocol_semantics')}")
    print(f"Communication baseline changed: {ans.get('14_communication_baseline_changed')}")
    for k, p in written.items():
        if not str(k).endswith("_md"):
            print(f"{k}: {p}")
    return ExitCode.SUCCESS


def _cmd_diagnose_buffer_semantics(args: argparse.Namespace) -> int:
    import json
    from apk_forensics.buffer_semantic_closure import (
        build_byte_processing_report,
        build_semantic_closure_report,
        write_semantic_reports,
    )
    from apk_forensics.communication_evidence import postprocess_communication_from_report

    report_path = Path(args.from_report).resolve()
    out_dir = Path(args.output).resolve()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    baseline_meta = None
    if args.baseline_meta:
        baseline_meta = json.loads(Path(args.baseline_meta).resolve().read_text(encoding="utf-8"))
    v13_closure = None
    if args.v13_closure and Path(args.v13_closure).is_file():
        v13_closure = json.loads(Path(args.v13_closure).resolve().read_text(encoding="utf-8"))

    expanded_comm = None
    if args.apk and Path(args.apk).is_file():
        cfg = {
            "enabled": True,
            "max_buffer_hops": 5,
            "max_parser_hops": 3,
            "max_message_hops": 3,
            "max_method_hops": 3,
            "max_dataflow_paths": 100,
            "max_object_nodes": 500,
            "interprocedural": True,
            "expand_interface_consumers": bool(args.expand_interface_consumers),
            "max_expand_extra": 80,
        }
        expanded_comm = postprocess_communication_from_report(
            report,
            Path(args.apk).resolve(),
            config=cfg,
            postprocessing_version=__version__,
        )
        # persist expanded communication for reproducibility
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "communication_evidence_expanded.json").write_text(
            json.dumps(expanded_comm, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    closure = build_semantic_closure_report(
        transport_report=report,
        v13_closure=v13_closure,
        expanded_comm=expanded_comm,
        baseline_meta=baseline_meta,
        provenance={
            "source_report": str(report_path),
            "apk": str(args.apk) if args.apk else None,
            "expand_interface_consumers": bool(args.expand_interface_consumers),
            "postprocessing_version": __version__,
            "max_field_hops": 2,
            "limits_raised": False,
        },
    )
    byte_report = build_byte_processing_report(expanded_comm)
    written = write_semantic_reports(out_dir, closure, byte_report)
    ans = closure.get("answers") or {}
    print(f"APK Forensics {__version__} diagnose-buffer-semantics")
    print(f"Source: {report_path}")
    print(f"Hypothesis: {ans.get('2_apk_or_analyzer')}")
    print(f"Byte processing (CASE-C): {ans.get('4_paths_reaching_byte_processing')}")
    print(f"Decoder candidates: {ans.get('16_decoder_encoder_candidate_exists')}")
    print(f"Protocol semantics UNKNOWN: {ans.get('20_protocol_semantics_still_unknown')}")
    print(f"Communication baseline changed: {ans.get('19_communication_baseline_changed')}")
    for k, p in written.items():
        print(f"{k}: {p}")
    return ExitCode.SUCCESS


def _cmd_calibrate(args: argparse.Namespace) -> int:
    import json
    from apk_forensics.coverage_analysis import annotate_paths
    from apk_forensics.resource_calibration import (
        build_coverage_report,
        build_resource_estimate_report,
        load_historical_runs,
        render_coverage_markdown,
        render_resource_estimate_markdown,
        sensitivity_matrix,
        write_report_pair,
    )
    from apk_forensics.resource_estimator import (
        ResourceEstimate,
        estimate_resources,
        fingerprint_apk as fp_apk,
        plan_factors_from_search_plan,
    )
    from apk_forensics.search_plan import load_search_plan as load_plan

    out_dir = Path(args.output).resolve()
    default_history = [
        Path("output/mybmw-v06/report.json"),
        Path("output/mybmw-v07/report.json"),
        Path("output/bmw-connected-600-v08/report.json"),
        Path("output/mybmw-v08/report.json"),
        Path("output/bmw-connected-600-v09/report.json"),
        Path("output/bmw-connected-600-v10/report.json"),
        Path("output/mybmw-v10/report.json"),
    ]
    history_paths = list(args.history) if args.history else default_history
    historical = load_historical_runs(history_paths)

    focus_path = args.focus_report
    if focus_path is None:
        cand = Path("output/bmw-connected-600-v10/report.json")
        focus_path = cand if cand.is_file() else (history_paths[-1] if history_paths else None)
    focus_report = None
    focus_est = None
    focus_act = None
    focus_label = None
    if focus_path and Path(focus_path).is_file():
        focus_report = json.loads(Path(focus_path).read_text(encoding="utf-8"))
        focus_label = Path(focus_path).parent.name
        est_d = (focus_report.get("resource") or {}).get("estimate") or {}
        focus_act = (focus_report.get("resource") or {}).get("actual") or {}
        if est_d.get("memory_mb") is not None:
            focus_est = ResourceEstimate(
                memory_mb=int(est_d["memory_mb"]),
                runtime_seconds=int(est_d.get("runtime_seconds") or 0),
                findings=int(est_d.get("findings") or 0),
                dex_contexts=int(est_d.get("dex_contexts") or 0),
                xrefs=int(est_d.get("xrefs") or 0),
                risk=str(est_d.get("risk") or "ok"),
                reasons=list(est_d.get("reasons") or []),
                factors=dict(est_d.get("factors") or {}),
                artifacts=list(est_d.get("artifacts") or []),
                breakdown=dict(est_d.get("breakdown") or {}),
            )
            # Rebuild breakdown if missing (older reports)
            if not focus_est.breakdown and args.apk and Path(args.apk).is_file():
                plan_path = args.plan or Path("plans/communication_evidence.yaml")
                plan = load_plan(Path(plan_path))
                rebuilt = estimate_resources(
                    [fp_apk(Path(args.apk))],
                    plan_factors_from_search_plan(plan),
                    get_resource_policy("standard"),
                )
                # Keep stored totals; attach live breakdown only if totals match
                if rebuilt.memory_mb == focus_est.memory_mb and rebuilt.runtime_seconds == focus_est.runtime_seconds:
                    focus_est.breakdown = rebuilt.breakdown

    sensitivity = None
    if args.apk and Path(args.apk).is_file():
        plan_path = args.plan or Path("plans/communication_evidence.yaml")
        plan = load_plan(Path(plan_path))
        sensitivity = sensitivity_matrix(fp_apk(Path(args.apk)), plan)

    res_report = build_resource_estimate_report(
        historical=historical,
        focus_estimate=focus_est,
        focus_actual=focus_act,
        sensitivity=sensitivity,
        focus_label=focus_label,
    )
    write_report_pair(
        out_dir,
        "RESOURCE_ESTIMATE_REPORT",
        res_report,
        render_resource_estimate_markdown(res_report),
    )

    # Coverage from focus (+ MyBMW) reports — annotate offline without re-scan
    def _cov_from_report(rep: dict) -> tuple[dict | None, dict | None, dict | None]:
        bt = rep.get("bluetooth_path") or {}
        eg = bt.get("evidence_graph") or {}
        ce = rep.get("communication_evidence") or {}
        t_paths = list(eg.get("evidence_paths") or [])
        c_paths = list(ce.get("paths") or [])
        retention = ce.get("method_retention") or (ce.get("provenance") or {}).get("method_retention")
        capped = bool((retention or {}).get("capped"))
        t_ann, t_sum = annotate_paths(t_paths) if t_paths else ([], None)
        c_ann, c_sum = annotate_paths(c_paths, retention_capped=capped) if c_paths else ([], None)
        if t_ann:
            eg = dict(eg)
            eg["evidence_paths"] = t_ann
            eg["coverage"] = t_sum
        if c_ann:
            ce = dict(ce)
            ce["paths"] = c_ann
            ce["coverage"] = c_sum
        return t_sum, c_sum, retention

    transport_cov = None
    comm_cov = None
    retention = None
    provenance = {}
    if focus_report:
        transport_cov, comm_cov, retention = _cov_from_report(focus_report)
        provenance = {
            "focus_report": str(Path(focus_path).resolve()) if focus_path else None,
            "engine_version": (focus_report.get("tool") or {}).get("version"),
            "plan_sha256": (focus_report.get("analysis") or {}).get("plan_sha256"),
            "artifact_sha256": (focus_report.get("input") or {}).get("sha256"),
            "postprocessing_version": __version__,
        }
    cov_report = build_coverage_report(
        transport_coverage=transport_cov,
        communication_coverage=comm_cov,
        retention=retention,
        provenance=provenance,
    )
    write_report_pair(
        out_dir,
        "COVERAGE_REPORT",
        cov_report,
        render_coverage_markdown(cov_report),
    )

    print(f"APK Forensics {__version__} calibrate")
    print(f"Output: {out_dir}")
    print(f"RESOURCE_ESTIMATE_REPORT: {out_dir / 'RESOURCE_ESTIMATE_REPORT.json'}")
    print(f"COVERAGE_REPORT: {out_dir / 'COVERAGE_REPORT.json'}")
    if focus_est:
        print(f"Focus estimate: {focus_est.memory_mb} MiB / {focus_est.runtime_seconds} s")
    if focus_act:
        print(
            f"Focus actual: {focus_act.get('peak_memory_mb')} MiB / "
            f"{focus_act.get('runtime_seconds')} s"
        )
    return ExitCode.SUCCESS


def _cmd_postprocess_communication(args: argparse.Namespace) -> int:
    import json
    from apk_forensics.communication_evidence import postprocess_communication_from_report
    from apk_forensics.report_writer import _render_communication_evidence_markdown
    from apk_forensics.search_plan import load_search_plan

    report_path = Path(args.from_report).resolve()
    apk_path = Path(args.apk).resolve()
    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = json.loads(report_path.read_text(encoding="utf-8"))

    plan_path = args.plan
    if plan_path is None:
        plan_path = Path(__file__).resolve().parents[2] / "plans" / "communication_evidence.yaml"
        if not plan_path.is_file():
            plan_path = Path("plans/communication_evidence.yaml")
    plan = load_search_plan(Path(plan_path))
    cfg = {
        "enabled": True,
        "interprocedural": plan.communication_interprocedural,
        "max_method_hops": plan.communication_max_method_hops,
        "max_field_hops": plan.communication_max_field_hops,
        "max_object_nodes": plan.communication_max_object_nodes,
        "max_dataflow_paths": plan.communication_max_dataflow_paths,
        "max_buffer_hops": plan.communication_max_buffer_hops,
        "max_parser_hops": plan.communication_max_parser_hops,
        "max_message_hops": plan.communication_max_message_hops,
    }
    comm = postprocess_communication_from_report(
        raw,
        apk_path,
        config=cfg,
        postprocessing_version=__version__,
    )
    # Preserve transport evidence classifications; only attach communication layer.
    raw["communication_evidence"] = comm
    raw["schema_version"] = "1.0"
    if isinstance(raw.get("tool"), dict):
        raw["tool"]["version"] = __version__
    if isinstance(raw.get("analysis"), dict):
        warnings = list(raw["analysis"].get("warnings") or [])
        warnings.extend(comm.get("warnings") or [])
        raw["analysis"]["warnings"] = warnings
        raw["analysis"]["engine_version"] = __version__

    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    json_path.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Prefer appending communication section to existing markdown when present.
    source_md = report_path.with_suffix(".md")
    if source_md.is_file():
        base_md = source_md.read_text(encoding="utf-8")
    else:
        base_md = (
            f"# APK Forensics postprocess-communication\n\n"
            f"Source report: `{report_path}`\n\n"
            f"Transport sections preserved in JSON; communication layer below.\n\n"
        )
    if "## Communication Evidence" not in base_md:
        extra = "\n".join(_render_communication_evidence_markdown(comm))
        md_path.write_text(base_md.rstrip() + "\n\n" + extra + "\n", encoding="utf-8")
    else:
        md_path.write_text(base_md, encoding="utf-8")

    cs = comm.get("summary") or {}
    print(f"APK Forensics {__version__} postprocess-communication")
    print(f"Source report: {report_path}")
    print(f"APK: {apk_path}")
    print(f"Plan: {plan.plan_name} sha256={plan.plan_sha256}")
    print(f"Communication paths: {cs.get('communication_paths', 0)}")
    print(f"Strongest: {cs.get('strongest_path_id')} ({cs.get('strongest_classification')})")
    print(f"Protocol semantics: {cs.get('protocol_semantics')}")
    print(f"JSON: {json_path}")
    print(f"Markdown: {md_path}")
    return ExitCode.SUCCESS


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else ExitCode.INVALID_ARGS
        return code if code is not None else ExitCode.INVALID_ARGS

    if args.command == "storage":
        return _cmd_storage(args)
    if args.command == "clean":
        return _cmd_clean(args)
    if args.command == "plan":
        return _cmd_plan(args)
    if args.command == "estimate":
        return _cmd_estimate(args)
    if args.command == "diagnose-field-coverage":
        return _cmd_diagnose_field_coverage(args)
    if args.command == "diagnose-transport-closure":
        return _cmd_diagnose_transport_closure(args)
    if args.command == "diagnose-buffer-semantics":
        return _cmd_diagnose_buffer_semantics(args)
    if args.command == "calibrate":
        return _cmd_calibrate(args)
    if args.command == "postprocess-communication":
        return _cmd_postprocess_communication(args)
    if args.command == "scan":
        return _cmd_scan(args)

    parser.print_help()
    return ExitCode.INVALID_ARGS


if __name__ == "__main__":
    raise SystemExit(main())

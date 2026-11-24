"""Command-line interface for apk-forensics."""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from apk_forensics import __version__
from apk_forensics.artifact_bundle import load_paths_from_bundle_arg
from apk_forensics.bundle_pipeline import run_bundle_pipeline
from apk_forensics.config import AnalysisConfig
from apk_forensics.errors import ApkForensicsError, ExitCode, InputError, InvalidApkError
from apk_forensics.logging_config import configure_logging
from apk_forensics.pipeline import run_pipeline
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

    plan_cmd = sub.add_parser("plan", help="Validate / show declarative SearchPlans.")
    plan_sub = plan_cmd.add_subparsers(dest="plan_command", required=True)
    plan_validate = plan_sub.add_parser("validate", help="Validate a SearchPlan without scanning.")
    plan_validate.add_argument("plan_path", type=Path, help="Path to SearchPlan YAML")
    plan_show = plan_sub.add_parser("show", help="Show normalized SearchPlan + plan_sha256.")
    plan_show.add_argument("plan_path", type=Path, help="Path to SearchPlan YAML")
    plan_show.add_argument("--json", action="store_true", help="Emit canonical JSON")
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
        if args.formats:
            config.formats = formats
        if args.include_raw:
            config.include_raw = True
        if args.query:
            config.dex_query = args.query

    profile_arg = resolve_profile_from_plan(search_plan, args.profile) if search_plan else args.profile

    workspace = discover_workspace()
    workspace.ensure()
    run_name = args.output.name if args.output else "scan"
    work = create_work_session(workspace, run_name=run_name, keep=config.keep_work)

    # Resolve input set
    paths: list[Path] = []
    try:
        if args.bundle:
            paths.extend(load_paths_from_bundle_arg(args.bundle))
        if args.apk_path is not None:
            paths.append(args.apk_path.resolve())
        if args.splits:
            for s in args.splits:
                paths.append(Path(s).resolve())
        # Deduplicate while preserving order
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
        work.cleanup()
        return ExitCode.INPUT_UNREADABLE

    if config.copy_input:
        print(
            "note: --copy-input records intent only; inputs are still analyzed in place "
            "(no automatic durable copy of user originals).",
            file=sys.stderr,
        )

    try:
        if len(paths) > 1 or args.bundle:
            bundle_report, outputs, _warnings = run_bundle_pipeline(
                paths,
                args.output,
                config=config,
                profile_path=profile_arg,
                work_session=work,
                search_plan=search_plan,
            )
            print(f"APK Forensics {__version__}")
            print(f"Mode: ArtifactBundle ({len(paths)} members)")
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

        # Single APK
        report, outputs, _warnings = run_pipeline(
            paths[0],
            args.output,
            config=config,
            profile_path=profile_arg,
            copy_input=config.copy_input,
            search_plan=search_plan,
        )
        work.cleanup()
    except InvalidApkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return ExitCode.INVALID_APK
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return getattr(exc, "exit_code", ExitCode.INPUT_UNREADABLE)
    except ApkForensicsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if args.debug:
            traceback.print_exc()
        work.cleanup()
        return getattr(exc, "exit_code", ExitCode.FATAL)
    except Exception as exc:  # noqa: BLE001
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
    if args.command == "scan":
        return _cmd_scan(args)

    parser.print_help()
    return ExitCode.INVALID_ARGS


if __name__ == "__main__":
    raise SystemExit(main())

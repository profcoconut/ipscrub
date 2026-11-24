"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import replace
from pathlib import Path

from .addresses import AddressError, Matcher, decode_address
from .plan import Plan
from .runner import run
from . import __version__

PROG = "ipscrub"

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_ERROR = 2


def _add_matcher_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("address")
    group.add_argument(
        "--address",
        action="append",
        default=[],
        metavar="IP",
        help="address to scrub; visible in the process table, prefer --address-b64",
    )
    group.add_argument(
        "--address-b64",
        action="append",
        default=[],
        metavar="B64",
        help="same address, base64 encoded (keeps it out of argv and shell history)",
    )
    group.add_argument(
        "--prefix-len",
        type=int,
        default=None,
        metavar="N",
        help="also match the enclosing network (default: /24 for IPv4, /64 for IPv6; 0 disables)",
    )
    group.add_argument(
        "--no-prefix",
        action="store_true",
        help="match only the exact addresses",
    )


def _add_plan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="DIR",
        help="directory to walk; repeatable (default: a standard Linux set)",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        metavar="N",
        help="skip files larger than this (default 200 MiB)",
    )
    parser.add_argument(
        "--no-journald",
        action="store_true",
        help="do not stop/start systemd-journald around journal deletion",
    )
    parser.add_argument(
        "--keep-journals",
        action="store_true",
        help="delete a journal file only when a plaintext match was found in it",
    )


def _build_matcher(args: argparse.Namespace) -> Matcher:
    raw = list(args.address)
    encoded = list(args.address_b64)
    # Space or comma separated, so a remote runner can pass several addresses
    # without putting them in argv.
    env = os.environ.get("IPSCRUB_ADDRESS_B64", "")
    encoded.extend(item for item in env.replace(",", " ").split() if item)

    addresses = [decode_address(item) for item in raw]
    addresses.extend(decode_address(item, encoded=True) for item in encoded)
    if not addresses:
        raise AddressError(
            "no address given: use --address, --address-b64, or IPSCRUB_ADDRESS_B64"
        )

    prefix_len = args.prefix_len
    if args.no_prefix:
        prefix_len = 0
    return Matcher.build(addresses, prefix_len=prefix_len, encode_prefixes=prefix_len != 0)


def _build_plan(args: argparse.Namespace) -> Plan:
    plan = Plan.for_roots(args.root or None)
    updates = {}
    if args.max_bytes is not None:
        updates["max_bytes"] = args.max_bytes
    if args.no_journald:
        updates["manage_journald"] = False
    if updates:
        plan = replace(plan, **updates)
    if args.keep_journals:
        plan = plan.with_keep_journals()
    return plan


def _print_human(outcome, matcher: Matcher, *, applied: bool) -> None:
    report = outcome.report
    if report.findings:
        print(f"# matches (network: {matcher.describe()})")
        for finding in report.findings:
            suffix = f"  [{finding.action.value}]" if finding.action and applied else ""
            print(f"  {finding.as_row()}{suffix}")
    print("# summary")
    for line in outcome.summary_lines():
        print(f"  {line}")

def _print_json(outcome, matcher: Matcher) -> None:
    report = outcome.report
    payload = {
        "network": matcher.describe(),
        "scanned": report.scanned,
        "dirty_files": report.dirty_files,
        "occurrences": report.occurrences,
        "removed_files": report.removed_files,
        "removed_occurrences": report.removed_occurrences,
        "skipped_large": report.skipped_large,
        "findings": [
            {
                "path": f.path,
                "full": f.full,
                "prefix": f.prefix,
                "reason": f.reason,
                "action": f.action.value if f.action else None,
            }
            for f in report.findings
        ],
        "failed": [{"path": f.path, "error": f.error} for f in report.failed],
        "residual": [{"path": f.path, "full": f.full, "prefix": f.prefix} for f in report.residual],
        "journald_restarted": outcome.journald_restarted,
    }
    print(json.dumps(payload, indent=2))


def _run_command(args: argparse.Namespace, *, apply: bool) -> int:
    try:
        matcher = _build_matcher(args)
    except AddressError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    plan = _build_plan(args)
    outcome = run(matcher, plan, apply=apply)

    if args.json:
        _print_json(outcome, matcher)
    else:
        _print_human(outcome, matcher, applied=apply)

    if apply:
        if not outcome.clean:
            print(f"{PROG}: residual matches remain", file=sys.stderr)
            return EXIT_FOUND
        return EXIT_CLEAN
    if outcome.report.findings:
        return EXIT_FOUND
    return EXIT_CLEAN

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Find and remove addresses (and their enclosing network) from files on a host. "
            "Read-only unless you run one of the cleaning commands."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="report matches, change nothing")
    _add_matcher_args(scan)
    _add_plan_args(scan)
    scan.add_argument("--json", action="store_true", help="machine readable output")

    clean = subparsers.add_parser("clean", help="remove the matches, then verify")
    _add_matcher_args(clean)
    _add_plan_args(clean)
    clean.add_argument("--json", action="store_true", help="machine readable output")

    verify = subparsers.add_parser("verify", help="alias for scan")
    _add_matcher_args(verify)
    _add_plan_args(verify)
    verify.add_argument("--json", action="store_true", help="machine readable output")

    remote = subparsers.add_parser(
        "remote",
        help="run on an EC2 instance through SSM Run Command",
        description=(
            "Ship this package to an instance and run it there. Needs the aws CLI on "
            "this machine and SSM agent on the target."
        ),
    )
    _add_matcher_args(remote)
    remote.add_argument("--instance", required=True, metavar="ID")
    remote.add_argument("--region", required=True)
    remote.add_argument("--apply", action="store_true", help="clean instead of only scanning")
    remote.add_argument("--profile", default=None, metavar="NAME")
    remote.add_argument("--timeout", type=int, default=2700, metavar="SECONDS")

    nightly = subparsers.add_parser(
        "nightly",
        help="discover this machine's address, clean it on the given hosts, report counts",
        description=(
            "One unattended pass, meant for a scheduled job: learn the public address, "
            "remember it, then clean every address in the rolling window on each named "
            "instance. Prints how many matches were found and how many were removed."
        ),
    )
    nightly.add_argument(
        "--instance", action="append", default=[], metavar="ID",
        help="EC2 instance to clean; repeatable",
    )
    nightly.add_argument("--region", required=True)
    nightly.add_argument("--profile", default=None, metavar="NAME")
    nightly.add_argument("--timeout", type=int, default=2700, metavar="SECONDS")
    nightly.add_argument(
        "--keep", type=int, default=None, metavar="N",
        help="how many past addresses to keep in scope (default 5)",
    )
    nightly.add_argument(
        "--address", default=None, metavar="IP",
        help="skip discovery and use this address (testing, or a known-egress box)",
    )
    nightly.add_argument(
        "--prefix-len", type=int, default=None, metavar="N",
        help="also match the enclosing network (default: /24, 0 disables)",
    )
    nightly.add_argument(
        "--delete-journals", action="store_true",
        help="delete journal files on the pattern rather than only on a real match",
    )
    nightly.add_argument(
        "--state-dir", default=None, metavar="DIR",
        help="where the address history and the latest report live",
    )
    nightly.add_argument("--json", action="store_true", help="machine readable output")

    parser.add_argument(
        "--version", action="version", version=f"{PROG} {__version__}"
    )

    return parser


def _run_nightly(args: argparse.Namespace) -> int:
    from .history import DEFAULT_KEEP
    from .nightly import (
        NightlyError,
        append_line,
        default_state_dir,
        run_nightly,
        write_latest,
    )

    if not args.instance:
        print(f"{PROG}: nightly needs at least one --instance", file=sys.stderr)
        return EXIT_ERROR

    state_dir = Path(args.state_dir) if args.state_dir else default_state_dir()

    def log(message: str) -> None:
        print(f"{PROG}: {message}", file=sys.stderr)

    try:
        report = run_nightly(
            args.instance,
            args.region,
            keep=args.keep if args.keep is not None else DEFAULT_KEEP,
            profile=args.profile,
            timeout=args.timeout,
            address=args.address,
            prefix_len=args.prefix_len,
            keep_journals=not args.delete_journals,
            store=state_dir / "addresses.json",
            log=log,
        )
    except NightlyError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    latest = write_latest(state_dir / "latest.txt", report)
    append_line(state_dir / "history.log", report.headline())

    if args.json:
        print(json.dumps(report.as_dict(), indent=2, ensure_ascii=False))
    else:
        print(report.headline())
        for line in report.detail_lines():
            print(f"  {line}")
        print(f"  report: {latest}")

    if report.failures:
        return EXIT_ERROR
    return EXIT_CLEAN if report.residual_files == 0 else EXIT_FOUND


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "remote":
            from .remote import run_remote

            return run_remote(args)
        if args.command == "nightly":
            return _run_nightly(args)
    except AddressError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.command in ("scan", "verify"):
        return _run_command(args, apply=False)
    if args.command == "clean":
        return _run_command(args, apply=True)
    parser.error("unknown command")
    return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Running a scrub: scan, then (optionally) clean, then verify."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

from .addresses import Matcher
from .plan import Action, Plan
from .scan import Finding, Report, apply_finding, scan_file, tree_has_needle, walk


@dataclass
class Outcome:
    report: Report
    journald_stopped: bool = False
    journald_restarted: bool = False

    @property
    def clean(self) -> bool:
        return not self.report.residual and not self.report.failed

    def summary_lines(self) -> list[str]:
        rep = self.report
        lines = [
            f"scanned files      : {rep.scanned}",
            f"files with matches : {rep.dirty_files}",
            f"occurrences        : {rep.occurrences}",
        ]
        if rep.applied:
            lines.append(f"removed files      : {rep.removed_files}")
            lines.append(f"removed occurrences: {rep.removed_occurrences}")
        unmeasured = rep.unmeasured
        if unmeasured:
            lines.append(
                f"rule-applied files : {len(unmeasured)} (removed without a readable match)"
            )
        if rep.applied:
            lines.append(f"files changed      : {len(rep.applied)}")
        if rep.failed:
            lines.append(f"failed to change   : {len(rep.failed)}")
            for finding in rep.failed:
                lines.append(f"  {finding.path}: {finding.error}")
        if rep.skipped_large:
            lines.append(f"skipped (too large): {len(rep.skipped_large)}")
            lines.extend(f"  {path}" for path in rep.skipped_large[:10])
        lines.append(f"residual files     : {len(rep.residual)}")
        for finding in rep.residual[:20]:
            lines.append(f"  left {finding.as_row()}")
        if self.journald_stopped:
            state = "restarted" if self.journald_restarted else "NOT RESTARTED"
            lines.append(f"journald           : stopped, {state}")
        return lines


def _journald(action: str) -> bool:
    try:
        result = subprocess.run(
            ["systemctl", action, "systemd-journald"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, ValueError):
        return False
    return result.returncode == 0


def _collect_specials(plan: Plan, matcher: Matcher) -> list[Finding]:
    """Expand the plan's special rules into concrete findings.

    A special rule wins over the generic walk: the SSM agent log is truncated
    even though the walk could have rewritten it.
    """
    findings: list[Finding] = []
    seen: set[str] = set()

    for special in plan.specials:
        paths = special.expand()
        if special.action is Action.DELETE_TREE:
            for path in paths:
                if path in seen or not os.path.isdir(path):
                    continue
                if tree_has_needle(path, matcher, plan):
                    seen.add(path)
                    findings.append(Finding(path=path, action=special.action))
            continue

        for path in paths:
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            if special.action is Action.DELETE and special.always:
                # Journal internals are compressed and deduplicated, so a miss
                # is not evidence of absence.  The rule fires on the pattern.
                findings.append(
                    Finding(path=path, action=special.action, reason="always-delete")
                )
                continue
            finding = scan_file(path, matcher, plan)
            if finding is not None:
                finding.action = special.action
                findings.append(finding)
    return findings


def _apply_order(finding: Finding) -> int:
    """Rewrites before removals: a removed parent would strand its children."""
    order = {
        Action.REWRITE_ATOMIC: 0,
        Action.REWRITE_INPLACE: 0,
        Action.TRUNCATE: 1,
        Action.DELETE: 2,
        Action.DELETE_TREE: 3,
    }
    return order.get(finding.action or Action.REWRITE_ATOMIC, 0)


def run(matcher: Matcher, plan: Plan | None = None, *, apply: bool = False) -> Outcome:
    """Scan the plan's roots; when *apply* is true, clean and verify."""
    plan = plan or Plan()
    report = Report()
    outcome = Outcome(report=report)

    specials = _collect_specials(plan, matcher)
    report.findings.extend(specials)
    walk(plan, matcher, report, excluded={finding.path for finding in specials})

    if not apply:
        return outcome

    needs_journald = any(finding.action is Action.DELETE for finding in report.findings)
    if plan.manage_journald and needs_journald and _journald("stop"):
        outcome.journald_stopped = True

    try:
        for finding in sorted(report.findings, key=_apply_order):
            apply_finding(finding, matcher)
            report.applied.append(finding)
    finally:
        if outcome.journald_stopped:
            outcome.journald_restarted = _journald("start")

    # Verify from scratch, so the verdict reflects what is on disk now rather
    # than what this process believes it did.  The re-walk populates findings,
    # which is exactly the residual set: anything still matching after cleaning.
    verify = Report()
    walk(plan, matcher, verify)
    report.residual = verify.findings
    return outcome

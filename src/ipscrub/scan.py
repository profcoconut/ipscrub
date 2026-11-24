"""Finding files that contain a needle, and rewriting them safely."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field

from .addresses import Matcher
from .plan import Action, Plan


@dataclass
class Finding:
    """One path and what was measured in it."""

    path: str
    full: int = 0
    prefix: int = 0
    action: Action | None = None
    error: str = ""
    #: Why this path is on the list: ``match``, ``always-delete``, ``always-truncate``.
    reason: str = "match"

    @property
    def total(self) -> int:
        return self.full + self.prefix

    @property
    def measured(self) -> bool:
        """False when the rule applies without a readable match."""
        return self.reason == "match"

    def as_row(self) -> str:
        counts = f"full={self.full}\tprefix={self.prefix}"
        if not self.measured:
            return f"{self.path}\t{counts}\t({self.reason})"
        return f"{self.path}\t{counts}"


@dataclass
class Report:
    scanned: int = 0
    skipped_large: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    applied: list[Finding] = field(default_factory=list)
    residual: list[Finding] = field(default_factory=list)

    @property
    def dirty_files(self) -> int:
        return len(self.findings)

    @property
    def occurrences(self) -> int:
        return sum(f.total for f in self.findings)

    @property
    def unmeasured(self) -> list[Finding]:
        """Findings a rule put on the list without a readable match."""
        return [f for f in self.findings if not f.measured]

    @property
    def failed(self) -> list[Finding]:
        return [f for f in self.applied if f.error]


def scan_file(path: str, matcher: Matcher, plan: Plan) -> Finding | None:
    """Scan one path. Returns ``None`` when the file is clean or unreadable."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > plan.max_bytes:
        return Finding(path=path, error="too-large")
    try:
        with open(path, "rb") as handle:
            blob = handle.read()
    except OSError:
        return None
    full, pref = matcher.count(blob)
    if not (full or pref):
        return None
    return Finding(path=path, full=full, prefix=pref, action=plan.write_action(path))


def _is_within(path: str, parents: set[str]) -> bool:
    """True when *path* is one of *parents* or sits inside one of them."""
    for parent in parents:
        if path == parent:
            return True
        prefix = parent if parent.endswith(os.sep) else parent + os.sep
        if path.startswith(prefix):
            return True
    return False


def walk(plan: Plan, matcher: Matcher, report: Report, excluded: set[str] | None = None) -> None:
    """Populate *report* from the plan's roots, skipping *excluded* subtrees.

    Subtrees are excluded rather than individual paths: a path already claimed
    by a special rule must not be scanned again, and neither must anything under
    a directory that rule is about to remove.
    """
    excluded = excluded or set()
    skip_dirs = set(plan.skip_dirs)
    for root in plan.roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if _is_within(dirpath, excluded):
                dirnames[:] = []
                continue
            dirnames[:] = [
                d
                for d in dirnames
                if d not in skip_dirs and not _is_within(os.path.join(dirpath, d), excluded)
            ]
            for name in filenames:
                path = os.path.join(dirpath, name)
                if os.path.islink(path) or path in excluded:
                    continue
                report.scanned += 1
                finding = scan_file(path, matcher, plan)
                if finding is None:
                    continue
                if finding.error == "too-large":
                    report.skipped_large.append(path)
                    continue
                report.findings.append(finding)


def tree_has_needle(path: str, matcher: Matcher, plan: Plan) -> bool:
    """Whether any readable file inside a tree needs scrubbing."""
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [d for d in dirnames if d not in plan.skip_dirs]
        for name in filenames:
            candidate = os.path.join(dirpath, name)
            try:
                if os.path.getsize(candidate) > plan.max_bytes:
                    continue
                with open(candidate, "rb") as handle:
                    blob = handle.read()
            except OSError:
                continue
            full, pref = matcher.count(blob)
            if full or pref:
                return True
    return False


def _atomic_replace(path: str, data: bytes) -> None:
    st = os.stat(path)
    directory = os.path.dirname(path) or "."
    handle, tmp = tempfile.mkstemp(dir=directory, prefix=".ipscrub-")
    try:
        with os.fdopen(handle, "wb") as fp:
            fp.write(data)
        os.chmod(tmp, stat.S_IMODE(st.st_mode))
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except (OSError, AttributeError):
            pass
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _inplace_replace(path: str, data: bytes) -> None:
    """Rewrite keeping the inode, for files a daemon holds open in append mode."""
    with open(path, "r+b") as handle:
        handle.write(data)
        handle.truncate()


def remove_tree(path: str) -> None:
    """Delete a directory tree, reporting failures instead of swallowing them."""
    shutil.rmtree(path)


def apply_finding(finding: Finding, matcher: Matcher) -> Finding:
    """Apply one finding's action. Returns the finding, annotated."""
    path = finding.path
    action = finding.action or Action.REWRITE_ATOMIC
    try:
        if action is Action.TRUNCATE:
            open(path, "wb").close()
            return finding
        if action is Action.DELETE_TREE:
            remove_tree(path)
            return finding
        with open(path, "rb") as handle:
            blob = handle.read()
        cleaned = matcher.redact(blob)
        if action is Action.REWRITE_INPLACE:
            _inplace_replace(path, cleaned)
        elif action is Action.DELETE:
            os.remove(path)
        else:
            _atomic_replace(path, cleaned)
    except OSError as exc:
        finding.error = f"{type(exc).__name__}: {exc.strerror or exc}"
    return finding

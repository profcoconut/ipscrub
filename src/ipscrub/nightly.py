"""One nightly pass: learn today's address, then clean it everywhere it matters.

The point of this module is that the numbers it reports are the ones the remote
run actually measured, not an inference from "the command succeeded".  A clean
run already scans and then applies, so a single invocation answers both halves
of the question the user asks every morning: how many did you find, and how many
did you remove.

Design notes that are not obvious:

* One invocation carries the whole address window.  Sending one command per
  address would mean one set of SSM footprints per address, and the footprints
  are the thing being cleaned.
* The window is loaded, extended with today's address, and saved before the
  remote run.  If the remote run fails, tomorrow's run still knows about the
  address that was in use today.  Losing the address because the cleanup failed
  is the worse failure.
* A failed instance does not abort the others.  A nightly job that dies on the
  third host is not a nightly job.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .addresses import AddressError, decode_address
from .history import DEFAULT_KEEP, History, HistoryError, default_path as history_path
from .remote import RemoteError, RemoteResult, execute

#: Endpoints that answer with a bare address.  Two are enough to agree; more is
#: just more chances to be rate limited while someone else's carrier is slow.
DISCOVERY_URLS: tuple[str, ...] = (
    "https://ipinfo.io/ip",
    "https://ifconfig.me/ip",
    "https://checkip.amazonaws.com",
)

DISCOVERY_TIMEOUT = 10


class NightlyError(RuntimeError):
    pass


def _fetch_text(url: str) -> str:
    """Fetch one discovery endpoint, ignoring the system proxy.

    On a machine running a local proxy client the proxied answer is the *exit
    node's* address, which is not the address a plain SSH session leaves
    behind.  Cleaning that address looks like success and accomplishes nothing.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        url, headers={"User-Agent": "curl/8.0.0", "Accept": "text/plain"}
    )
    with opener.open(request, timeout=DISCOVERY_TIMEOUT) as response:
        return response.read(200).decode("utf-8", "replace").strip()


def discover_address(urls: tuple[str, ...] = DISCOVERY_URLS) -> str:
    """Ask the internet what this machine looks like from outside.

    A local interface address is useless here: behind NAT the address that
    appears in a remote host's logs is the carrier's, not this machine's.
    """
    problems: list[str] = []
    for url in urls:
        try:
            text = _fetch_text(url)
        except (urllib.error.URLError, OSError, socket.timeout) as exc:
            problems.append(f"{url}: {exc}")
            continue
        # Some of these answer with an IPv6 address depending on routing, and a
        # bare v6 spelling occasionally arrives wrapped in markup.
        candidate = text.split()[0].strip() if text else ""
        try:
            address = decode_address(candidate)
        except AddressError as exc:
            problems.append(f"{url}: {exc}")
            continue
        if "." in address:
            return address
        problems.append(f"{url}: only an IPv6 address ({address})")
    raise NightlyError("no IPv4 address from any endpoint:\n  " + "\n  ".join(problems))


@dataclass
class InstanceReport:
    instance: str
    status: str
    found_files: int = 0
    found_occurrences: int = 0
    removed_files: int = 0
    removed_occurrences: int = 0
    residual_files: int = 0
    error: str = ""
    command_id: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def as_line(self) -> str:
        if not self.ok:
            return f"{self.instance}  FAILED  {self.error}"
        return (
            f"{self.instance}  found {self.found_occurrences} in {self.found_files} files, "
            f"removed {self.removed_occurrences} from {self.removed_files} files, "
            f"residual {self.residual_files}"
        )


@dataclass
class NightlyReport:
    address: str
    window: list[str]
    evicted: list[str] = field(default_factory=list)
    instances: list[InstanceReport] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def found_occurrences(self) -> int:
        return sum(i.found_occurrences for i in self.instances)

    @property
    def removed_occurrences(self) -> int:
        return sum(i.removed_occurrences for i in self.instances)

    @property
    def found_files(self) -> int:
        return sum(i.found_files for i in self.instances)

    @property
    def removed_files(self) -> int:
        return sum(i.removed_files for i in self.instances)

    @property
    def residual_files(self) -> int:
        return sum(i.residual_files for i in self.instances)

    @property
    def failures(self) -> list[InstanceReport]:
        return [i for i in self.instances if not i.ok]

    @property
    def clean(self) -> bool:
        return not self.failures and self.residual_files == 0

    def headline(self) -> str:
        """The one line that answers the question that was actually asked."""
        return (
            f"{self.started_at:%Y-%m-%d %H:%M} UTC  "
            f"found {self.found_occurrences} in {self.found_files} files, "
            f"removed {self.removed_occurrences} from {self.removed_files} files"
            + (f", {self.residual_files} left" if self.residual_files else "")
            + (f", {len(self.failures)} host(s) failed" if self.failures else "")
        )

    def detail_lines(self) -> list[str]:
        lines = [
            f"address   : {self.address}",
            f"window    : {len(self.window)} address(es) in scope",
        ]
        if self.evicted:
            lines.append(f"dropped   : {', '.join(self.evicted)} (window is full)")
        for instance in self.instances:
            lines.append(f"  {instance.as_line()}")
        return lines

    def as_dict(self) -> dict:
        return {
            "started_at": self.started_at.isoformat(),
            "address": self.address,
            "window": self.window,
            "evicted": self.evicted,
            "found_occurrences": self.found_occurrences,
            "removed_occurrences": self.removed_occurrences,
            "found_files": self.found_files,
            "removed_files": self.removed_files,
            "residual_files": self.residual_files,
            "clean": self.clean,
            "instances": [
                {
                    "instance": i.instance,
                    "status": i.status,
                    "found_files": i.found_files,
                    "found_occurrences": i.found_occurrences,
                    "removed_files": i.removed_files,
                    "removed_occurrences": i.removed_occurrences,
                    "residual_files": i.residual_files,
                    "error": i.error,
                    "command_id": i.command_id,
                }
                for i in self.instances
            ],
        }


def _instance_report(result: RemoteResult) -> InstanceReport:
    report = InstanceReport(
        instance=result.instance,
        status=result.status,
        command_id=result.command_id,
    )
    if not result.ok:
        report.error = result.error
        return report
    payload = result.payload or {}
    report.found_files = int(payload.get("dirty_files", 0))
    report.found_occurrences = int(payload.get("occurrences", 0))
    report.removed_files = int(payload.get("removed_files", 0))
    report.removed_occurrences = int(payload.get("removed_occurrences", 0))
    report.residual_files = len(payload.get("residual") or [])
    failed = payload.get("failed") or []
    if failed:
        report.error = f"{len(failed)} file(s) could not be changed"
    return report


def run_nightly(
    instances: list[str],
    region: str,
    *,
    keep: int = DEFAULT_KEEP,
    profile: str | None = None,
    timeout: int = 600,
    address: str | None = None,
    prefix_len: int | None = None,
    keep_journals: bool = True,
    store: Path | None = None,
    log: Callable[[str], None] | None = None,
) -> NightlyReport:
    """Discover, remember, clean, and describe what happened."""
    log = log or (lambda message: None)
    store = store or history_path()

    address = address or discover_address()
    log(f"address {address}")

    history = History.load(store, keep=keep)
    evicted = history.evicted_by(address)
    history.add(address)
    saved = history.save(store)
    log(f"history {saved} now holds {len(history)} address(es)")

    report = NightlyReport(address=address, window=list(history.addresses), evicted=evicted)

    # Every address in the window travels in one payload, base64 encoded, so the
    # remote side never receives a readable spelling of any of them.
    encoded = [_encode(item) for item in report.window]

    for instance in instances:
        log(f"running on {instance}")
        try:
            result = execute(
                instance,
                region,
                encoded,
                apply=True,
                prefix_len=prefix_len,
                profile=profile,
                timeout=timeout,
                extra_flags=["--keep-journals"] if keep_journals else None,
            )
        except RemoteError as exc:
            report.instances.append(
                InstanceReport(instance=instance, status="Error", error=str(exc))
            )
            continue
        report.instances.append(_instance_report(result))

    return report


def _encode(address: str) -> str:
    import base64

    return base64.b64encode(address.encode("ascii")).decode("ascii")


def append_line(path: Path, line: str) -> Path:
    """Append one line to a log that outlives any single night."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fp:
        fp.write(line + "\n")
    return path


def write_latest(path: Path, report: NightlyReport) -> Path:
    """Overwrite the human-readable summary, so there is one file worth opening."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join([report.headline(), "", *report.detail_lines(), ""]), encoding="utf-8"
    )
    return path


def default_state_dir() -> Path:
    return history_path().parent

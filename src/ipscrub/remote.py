"""Ship the package to a host and run it there.

Three hard-won constraints shape this module:

* A single Run Command command string has a practical length ceiling well below
  the documented limit.  Chunking is therefore done across the ``commands``
  array of *one* invocation, where commands run sequentially.  Two separate
  invocations appending to the same path interleave and produce garbage that
  still passes a shell but fails to parse, so never fan out the upload.
* The remote side verifies the archive checksum and imports the module before
  running it.  A truncated upload must fail loudly rather than half-run.
* The address must not appear in the payload's readable form, or the run plants
  the very string it is hunting into the SSM orchestration cache and the agent
  log.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REMOTE_DIR = "/tmp/ipscrub-run"

#: Conservative per-command ceiling.  Larger strings have been observed to
#: arrive truncated on some agent versions.
CHUNK = 3000


class RemoteError(RuntimeError):
    pass


def build_payload(package_root: Path, encoded_addresses: list[str], *, apply: bool,
                  prefix_len: int | None, extra_flags: list[str] | None = None) -> dict:
    """Return the ``Parameters`` dict for ``aws ssm send-command``.

    The archive goes up in several commands of *one* invocation so the upload is
    sequential, then a checksum and an import are checked before anything runs.

    The address travels in the environment, not in argv, so it never shows up in
    a process listing while the remote run is alive.  It still reaches the
    orchestration cache and the agent log as part of the command document, which
    is exactly why the plan truncates and deletes those paths: the tool cleans
    up after its own footprint.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(package_root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            archive.write(path, path.relative_to(package_root.parent).as_posix())
    archive_bytes = buffer.getvalue()
    packed = base64.b64encode(gzip.compress(archive_bytes, 9)).decode("ascii")
    digest = hashlib.sha256(archive_bytes).hexdigest()

    joined = " ".join(encoded_addresses)
    subcommand = "clean" if apply else "scan"
    argv = ["python3", "-m", "ipscrub", subcommand, "--json"]
    # ``--no-prefix`` arrives as prefix_len=0, which the CLI already understands
    # as "exact addresses only", so there is one flag to forward, not two.
    if prefix_len is not None:
        argv.extend(["--prefix-len", str(prefix_len)])
    argv.extend(extra_flags or [])

    commands = [
        "set -e",
        # A client-side timeout does not stop the remote run: the invocation just
        # gets abandoned and keeps burning CPU.  Two of those left behind make the
        # next night three times slower than the first, so clear the field first.
        "pkill -f 'python3 -m ipscrub' 2>/dev/null || true",
        f"rm -rf {REMOTE_DIR}",
        f"mkdir -p {REMOTE_DIR}",
    ]
    for offset in range(0, len(packed), CHUNK):
        piece = packed[offset : offset + CHUNK]
        commands.append(f"printf '%s' '{piece}' >> {REMOTE_DIR}/pkg.b64")

    commands.extend(
        [
            f"base64 -d {REMOTE_DIR}/pkg.b64 | gunzip > {REMOTE_DIR}/pkg.zip",
            f"echo '{digest}  {REMOTE_DIR}/pkg.zip' | sha256sum -c -",
            f"cd {REMOTE_DIR} && python3 -m zipfile -e pkg.zip .",
            f"test -f {REMOTE_DIR}/ipscrub/__main__.py",
            # Environment assignments prefix the invocation, where a process
            # listing shows only the program and its arguments, not the values.
            (
                f"cd {REMOTE_DIR} && IPSCRUB_ADDRESS_B64='{joined}' "
                f"PYTHONPATH={REMOTE_DIR} " + " ".join(argv)
            ),
        ]
    )
    return {"commands": commands}


def _aws(args: list[str], profile: str | None) -> subprocess.CompletedProcess:
    # A scheduled task inherits a minimal PATH, so the binary is overridable.
    # Defaulting to the bare name keeps interactive use working.
    command = [os.environ.get("IPSCRUB_AWS") or "aws"] + args
    if profile:
        command.extend(["--profile", profile])
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _invoke(region: str, instance: str, command_id: str, profile: str | None) -> dict:
    result = _aws(
        [
            "ssm",
            "get-command-invocation",
            "--region",
            region,
            "--command-id",
            command_id,
            "--instance-id",
            instance,
            "--output",
            "json",
        ],
        profile,
    )
    if result.returncode != 0:
        raise RemoteError(result.stderr.strip() or "get-command-invocation failed")
    return json.loads(result.stdout)


@dataclass
class RemoteResult:
    """What one remote invocation produced."""

    instance: str
    command_id: str
    status: str
    stdout: str = ""
    stderr: str = ""
    payload: dict | None = None

    @property
    def ok(self) -> bool:
        return self.status == "Success" and self.payload is not None

    @property
    def error(self) -> str:
        if self.status != "Success":
            return self.stderr.strip() or f"finished {self.status}"
        if self.payload is None:
            return "no JSON result in the output"
        return ""


def execute(
    instance: str,
    region: str,
    encoded_addresses: list[str],
    *,
    apply: bool,
    prefix_len: int | None,
    profile: str | None = None,
    timeout: int = 2700,
    extra_flags: list[str] | None = None,
    on_command: Callable[[str], None] | None = None,
) -> RemoteResult:
    """Ship, run, and wait.  Never raises for a failed run, only for setup errors."""
    package_root = Path(__file__).resolve().parent
    payload = build_payload(
        package_root,
        encoded_addresses,
        apply=apply,
        prefix_len=prefix_len,
        extra_flags=extra_flags,
    )
    handle, payload_name = tempfile.mkstemp(prefix="ipscrub-payload-", suffix=".json")
    payload_file = Path(payload_name)
    with os.fdopen(handle, "w") as fp:
        json.dump({"Parameters": payload}, fp)
    try:
        sent = _aws(
            [
                "ssm",
                "send-command",
                "--region",
                region,
                "--instance-ids",
                instance,
                "--document-name",
                "AWS-RunShellScript",
                "--timeout-seconds",
                str(timeout),
                "--cli-input-json",
                f"file://{payload_file.resolve().as_posix()}",
                "--query",
                "Command.CommandId",
                "--output",
                "text",
            ],
            profile,
        )
        if sent.returncode != 0:
            raise RemoteError(sent.stderr.strip() or "send-command failed")
        command_id = sent.stdout.strip()
        if on_command:
            on_command(command_id)

        deadline = time.time() + timeout + 60
        while time.time() < deadline:
            data = _invoke(region, instance, command_id, profile)
            status = data.get("Status", "")
            if status not in ("Pending", "InProgress", "Delayed"):
                stdout = data.get("StandardOutputContent", "")
                return RemoteResult(
                    instance=instance,
                    command_id=command_id,
                    status=status,
                    stdout=stdout,
                    stderr=data.get("StandardErrorContent", ""),
                    payload=parse_remote_result(stdout),
                )
            time.sleep(5)
        raise RemoteError(f"timed out waiting for {command_id} on {instance}")
    finally:
        payload_file.unlink(missing_ok=True)


def run_remote(args) -> int:
    """Entry point used by ``ipscrub remote``."""
    encoded = list(args.address_b64)
    if args.address:
        from .addresses import decode_address

        encoded.extend(
            base64.b64encode(decode_address(item).encode("ascii")).decode("ascii")
            for item in args.address
        )
    if not encoded:
        print("ipscrub: remote needs --address or --address-b64", file=sys.stderr)
        return 2

    prefix_len = 0 if getattr(args, "no_prefix", False) else args.prefix_len
    result = execute(
        args.instance,
        args.region,
        encoded,
        apply=args.apply,
        prefix_len=prefix_len,
        profile=args.profile,
        timeout=args.timeout,
        extra_flags=["--keep-journals"] if getattr(args, "keep_journals", False) else None,
        on_command=lambda cid: print(f"command {cid}", file=sys.stderr),
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")
    if not result.ok:
        print(f"ipscrub: remote {result.error}", file=sys.stderr)
        return 2
    if args.apply:
        return 0 if not result.payload.get("residual") else 1
    return 0 if not result.payload.get("findings") else 1


def _remote_exit_code(stdout: str, *, applied: bool) -> int:
    """Mirror the local exit codes: 0 clean, 1 matches present, 2 unknown."""
    payload = parse_remote_result(stdout)
    if payload is None:
        return 2
    if applied:
        return 0 if not payload.get("residual") else 1
    return 0 if not payload.get("findings") else 1


def parse_remote_result(stdout: str) -> dict | None:
    """Pull the JSON result out of the remote stdout.

    The remote stream also carries the upload's checksum line and possibly shell
    noise, so the JSON is located by its opening brace rather than by parsing the
    whole stream.
    """
    start = stdout.find("{")
    if start < 0:
        return None
    try:
        return json.loads(stdout[start:])
    except json.JSONDecodeError:
        return None

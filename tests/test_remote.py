"""The SSM remote runner: payload shape and exit-code mapping.

Nothing here talks to AWS. What matters is that the address never lands in the
payload in readable form, and that the payload is small enough to send in one
command.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from ipscrub.remote import _remote_exit_code, build_payload

ADDRESS = "203.0.113.9"
ENCODED = base64.b64encode(ADDRESS.encode()).decode()

PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "ipscrub"


def payload_script(**kwargs) -> str:
    params = build_payload(PACKAGE_ROOT, kwargs.pop("addresses", [ENCODED]), **kwargs)
    return "\n".join(params["commands"])


class TestPayload:
    def test_address_absent_in_readable_form(self):
        script = payload_script(apply=False, prefix_len=None)
        assert ADDRESS not in script

    def test_encoded_address_goes_through_the_environment(self):
        script = payload_script(apply=False, prefix_len=None)
        assert f"IPSCRUB_ADDRESS_B64='{ENCODED}'" in script

    def test_address_is_not_in_argv(self):
        script = payload_script(apply=False, prefix_len=None)
        run_line = script.splitlines()[-1]
        # everything after the environment assignments is what `ps` would show
        argv = run_line.split("python3", 1)[1]
        assert ENCODED not in argv, "argv is visible to ps on the remote host"
        assert ADDRESS not in argv

    def test_each_command_under_the_ceiling(self):
        params = build_payload(PACKAGE_ROOT, [ENCODED], apply=False, prefix_len=None)
        assert params["commands"], "payload must not be empty"
        longest = max(len(item) for item in params["commands"])
        assert longest < 4000, "a single command string can arrive truncated above this"

    def test_upload_is_sequential_within_one_invocation(self):
        params = build_payload(PACKAGE_ROOT, [ENCODED], apply=False, prefix_len=None)
        appends = [c for c in params["commands"] if ">> /tmp/ipscrub-run/pkg.b64" in c]
        assert len(appends) > 1, "the archive needs more than one command to fit"
        # the first append must be preceded by the directory reset, in order
        first = params["commands"].index(appends[0])
        assert "rm -rf /tmp/ipscrub-run" in params["commands"][:first]
        assert "mkdir -p /tmp/ipscrub-run" in params["commands"][:first]

    def test_starts_by_resetting_the_run_directory(self):
        params = build_payload(PACKAGE_ROOT, [ENCODED], apply=False, prefix_len=None)
        reset = params["commands"].index("rm -rf /tmp/ipscrub-run")
        upload = next(
            i for i, c in enumerate(params["commands"]) if c.startswith("printf '%s'")
        )
        assert reset < upload, "the run directory must be cleared before the upload"

    def test_clears_an_abandoned_run_before_starting(self):
        """A client timeout leaves the remote process running; two of those
        make the next pass several times slower."""
        params = build_payload(PACKAGE_ROOT, [ENCODED], apply=False, prefix_len=None)
        commands = params["commands"]
        killer = next(i for i, c in enumerate(commands) if c.startswith("pkill -f"))
        executed = next(i for i, c in enumerate(commands) if c.startswith("cd /tmp/ipscrub-run"))
        assert killer < executed

    def test_checksum_is_verified_before_running(self):
        params = build_payload(PACKAGE_ROOT, [ENCODED], apply=False, prefix_len=None)
        verified = next(i for i, c in enumerate(params["commands"]) if "sha256sum -c" in c)
        executed = next(
            i
            for i, c in enumerate(params["commands"])
            if "IPSCRUB_ADDRESS_B64=" in c
        )
        assert verified < executed

    def test_extract_is_verified_before_running(self):
        params = build_payload(PACKAGE_ROOT, [ENCODED], apply=False, prefix_len=None)
        checked = next(i for i, c in enumerate(params["commands"]) if "__main__.py" in c)
        executed = next(
            i
            for i, c in enumerate(params["commands"])
            if "IPSCRUB_ADDRESS_B64=" in c
        )
        assert checked < executed

    def test_scan_has_no_clean_subcommand(self):
        script = payload_script(apply=False, prefix_len=None)
        assert "ipscrub scan --json" in script
        assert "ipscrub clean --json" not in script

    def test_apply_uses_clean(self):
        script = payload_script(apply=True, prefix_len=None)
        assert "ipscrub clean --json" in script

    def test_prefix_len_is_forwarded(self):
        script = payload_script(apply=False, prefix_len=16)
        assert "--prefix-len 16" in script

    def test_package_sources_are_included(self):
        script = payload_script(apply=False, prefix_len=None)
        import gzip
        import io
        import re
        import zipfile

        chunks = re.findall(r"printf '%s' '([A-Za-z0-9+/=]+)'", script)
        assert chunks, "the archive must be uploaded in base64 chunks"
        archive = zipfile.ZipFile(io.BytesIO(gzip.decompress(base64.b64decode("".join(chunks)))))
        names = archive.namelist()
        assert "ipscrub/runner.py" in names
        assert "ipscrub/cli.py" in names
        for name in names:
            assert ADDRESS not in archive.read(name).decode(), f"{name} contains the address"


class TestRemoteExitCode:
    def test_clean_scan_is_zero(self):
        assert _remote_exit_code(json.dumps({"findings": []}), applied=False) == 0

    def test_scan_with_findings_is_one(self):
        payload = json.dumps({"findings": [{"path": "/var/log/syslog"}]})
        assert _remote_exit_code(payload, applied=False) == 1

    def test_clean_run_is_zero(self):
        assert _remote_exit_code(json.dumps({"residual": []}), applied=True) == 0

    def test_clean_run_with_residual_is_one(self):
        payload = json.dumps({"residual": [{"path": "/var/log/syslog"}]})
        assert _remote_exit_code(payload, applied=True) == 1

    def test_noise_before_json_is_tolerated(self):
        payload = "some banner\n" + json.dumps({"findings": []})
        assert _remote_exit_code(payload, applied=False) == 0

    def test_garbage_is_two(self):
        assert _remote_exit_code("not json", applied=False) == 2

"""CLI behaviour: exit codes, address secrecy, output shape."""

from __future__ import annotations

import base64
import json

import pytest

from ipscrub.cli import main

ADDRESS = "203.0.113.9"
ENCODED = base64.b64encode(ADDRESS.encode()).decode()


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class TestExitCodes:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        assert "ipscrub" in capsys.readouterr().out

    def test_scan_clean_is_zero(self, tmp_path, capsys):
        write(tmp_path / "a.log", "nothing\n")
        code = main(["scan", "--address", ADDRESS, "--root", str(tmp_path)])
        assert code == 0

    def test_scan_with_matches_is_one(self, tmp_path, capsys):
        write(tmp_path / "a.log", f"{ADDRESS}\n")
        code = main(["scan", "--address", ADDRESS, "--root", str(tmp_path)])
        assert code == 1

    def test_clean_then_scan_is_zero(self, tmp_path, capsys):
        write(tmp_path / "a.log", f"{ADDRESS}\n")
        assert main(["clean", "--address", ADDRESS, "--root", str(tmp_path)]) == 0
        assert main(["scan", "--address", ADDRESS, "--root", str(tmp_path)]) == 0

    def test_bad_address_is_two(self, tmp_path, capsys):
        assert main(["scan", "--address", "nope", "--root", str(tmp_path)]) == 2

    def test_missing_address_is_two(self, tmp_path, capsys):
        assert main(["scan", "--root", str(tmp_path)]) == 2


class TestAddressSecrecy:
    def test_scan_does_not_change_files(self, tmp_path, capsys):
        target = write(tmp_path / "a.log", f"x {ADDRESS}\n")
        main(["scan", "--address", ADDRESS, "--root", str(tmp_path)])
        assert ADDRESS in target.read_text()

    def test_encoded_address_is_accepted(self, tmp_path, capsys):
        write(tmp_path / "a.log", f"{ADDRESS}\n")
        assert main(["scan", "--address-b64", ENCODED, "--root", str(tmp_path)]) == 1

    def test_report_does_not_leak_the_host_address(self, tmp_path, capsys):
        write(tmp_path / "a.log", f"{ADDRESS}\n")
        main(["scan", "--address", ADDRESS, "--root", str(tmp_path)])
        out = capsys.readouterr().out
        assert ADDRESS not in out, "the report must describe the network, not the host"
        assert "203.0.113.0/24" in out

    def test_env_var_is_accepted(self, tmp_path, capsys, monkeypatch):
        write(tmp_path / "a.log", f"{ADDRESS}\n")
        monkeypatch.setenv("IPSCRUB_ADDRESS_B64", ENCODED)
        assert main(["scan", "--root", str(tmp_path)]) == 1


class TestNoPrefix:
    def test_no_prefix_ignores_neighbour_hosts(self, tmp_path, capsys):
        write(tmp_path / "a.log", "peer 203.0.113.250\n")
        assert main(["scan", "--address", ADDRESS, "--no-prefix", "--root", str(tmp_path)]) == 0

    def test_prefix_catches_neighbour_hosts(self, tmp_path, capsys):
        write(tmp_path / "a.log", "peer 203.0.113.250\n")
        assert main(["scan", "--address", ADDRESS, "--root", str(tmp_path)]) == 1


class TestJsonOutput:
    def test_json_is_parseable(self, tmp_path, capsys):
        write(tmp_path / "a.log", f"{ADDRESS} {ADDRESS}\n")
        main(["scan", "--address", ADDRESS, "--root", str(tmp_path), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["dirty_files"] == 1
        assert payload["occurrences"] == 2
        assert payload["network"] == "203.0.113.0/24"

    def test_json_after_clean_reports_no_residual(self, tmp_path, capsys):
        write(tmp_path / "a.log", f"{ADDRESS}\n")
        main(["clean", "--address", ADDRESS, "--root", str(tmp_path), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["residual"] == []


class TestRoots:
    def test_multiple_roots(self, tmp_path, capsys):
        write(tmp_path / "one" / "a.log", "clean\n")
        write(tmp_path / "two" / "b.log", f"{ADDRESS}\n")
        code = main(
            [
                "scan",
                "--address",
                ADDRESS,
                "--root",
                str(tmp_path / "one"),
                "--root",
                str(tmp_path / "two"),
            ]
        )
        assert code == 1

    def test_missing_root_is_ignored(self, tmp_path, capsys):
        code = main(["scan", "--address", ADDRESS, "--root", str(tmp_path / "nope")])
        assert code == 0

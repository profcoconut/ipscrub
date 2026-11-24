"""The nightly pass: what it reports, and what it does when a host fails.

These tests never touch AWS.  ``execute`` is replaced with a stub, which is the
whole reason the module keeps the SSM call behind one function: the arithmetic
that answers "how many did you find, how many did you remove" is testable
without a network.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ipscrub import nightly
from ipscrub.nightly import (
    NightlyError,
    NightlyReport,
    InstanceReport,
    run_nightly,
)


def fake_payload(**overrides):
    payload = {
        "dirty_files": 4,
        "occurrences": 868,
        "removed_files": 4,
        "removed_occurrences": 868,
        "residual": [],
        "failed": [],
    }
    payload.update(overrides)
    return payload


def stub_execute(payloads, *, calls=None, raise_for=()):
    """Return an ``execute`` replacement keyed by instance id."""

    def execute(instance, region, addresses, *, apply, **kwargs):
        if calls is not None:
            calls.append(
                {"instance": instance, "region": region, "addresses": list(addresses), "apply": apply}
            )
        if instance in raise_for:
            raise nightly.RemoteError("ssm is down")
        payload = payloads.get(instance, fake_payload())
        return nightly.RemoteResult(
            instance=instance,
            command_id="cmd-1",
            status="Success",
            stdout="{}",
            payload=payload,
        )

    return execute


@pytest.fixture(autouse=True)
def _no_history_leak(tmp_path, monkeypatch):
    """Never read or write the real state directory during tests."""
    monkeypatch.setenv("IPSCRUB_HISTORY", str(tmp_path / "state" / "addresses.json"))


def test_reports_found_and_removed_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(nightly, "execute", stub_execute({"i-1": fake_payload()}))

    report = run_nightly(
        ["i-1"], "ap-northeast-1", address="203.0.113.10", store=tmp_path / "a.json"
    )

    assert report.found_occurrences == 868
    assert report.removed_occurrences == 868
    assert report.found_files == 4
    assert report.removed_files == 4
    assert report.residual_files == 0
    assert report.clean is True


def test_headline_states_both_numbers(tmp_path, monkeypatch):
    monkeypatch.setattr(nightly, "execute", stub_execute({"i-1": fake_payload()}))

    report = run_nightly(
        ["i-1"], "ap-northeast-1", address="203.0.113.10", store=tmp_path / "a.json"
    )

    line = report.headline()

    assert "found 868 in 4 files" in line
    assert "removed 868 from 4 files" in line


def test_defers_to_the_remote_measurement_not_the_local_plan(tmp_path, monkeypatch):
    """The counts come from the host that was cleaned, not from an assumption."""
    monkeypatch.setattr(
        nightly,
        "execute",
        stub_execute({"i-1": fake_payload(dirty_files=2, occurrences=7, removed_files=2,
                                          removed_occurrences=6)}),
    )

    report = run_nightly(
        ["i-1"], "ap-northeast-1", address="203.0.113.10", store=tmp_path / "a.json"
    )

    assert report.found_occurrences == 7
    assert report.removed_occurrences == 6


def test_residual_matches_make_the_run_not_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(
        nightly, "execute", stub_execute({"i-1": fake_payload(residual=[{"path": "/tmp/x"}])})
    )

    report = run_nightly(
        ["i-1"], "ap-northeast-1", address="203.0.113.10", store=tmp_path / "a.json"
    )

    assert report.residual_files == 1
    assert report.clean is False
    assert "1 left" in report.headline()


def test_one_dead_host_does_not_stop_the_others(tmp_path, monkeypatch):
    monkeypatch.setattr(
        nightly,
        "execute",
        stub_execute({"i-1": fake_payload(), "i-2": fake_payload()}, raise_for=("i-2",)),
    )

    report = run_nightly(
        ["i-1", "i-2", "i-3"],
        "ap-northeast-1",
        address="203.0.113.10",
        store=tmp_path / "a.json",
    )

    assert [i.instance for i in report.instances] == ["i-1", "i-2", "i-3"]
    assert report.failures[0].instance == "i-2"
    assert report.failures[0].ok is False
    assert report.clean is False
    assert "1 host(s) failed" in report.headline()


def test_a_host_that_could_not_change_a_file_is_not_reported_ok(tmp_path, monkeypatch):
    monkeypatch.setattr(
        nightly,
        "execute",
        stub_execute({"i-1": fake_payload(failed=[{"path": "/var/log/syslog"}])}),
    )

    report = run_nightly(
        ["i-1"], "ap-northeast-1", address="203.0.113.10", store=tmp_path / "a.json"
    )

    assert report.failures[0].instance == "i-1"


def test_todays_address_joins_the_window_and_travels_in_one_call(tmp_path, monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        nightly, "execute", stub_execute({}, calls=calls)
    )
    store = tmp_path / "a.json"
    nightly.History(addresses=["198.51.100.4"], keep=5).save(store)

    report = run_nightly(["i-1"], "ap-northeast-1", address="203.0.113.10", store=store)

    assert report.window == ["198.51.100.4", "203.0.113.10"]
    assert len(calls) == 1
    assert calls[0]["apply"] is True
    assert len(calls[0]["addresses"]) == 2


def test_the_address_is_saved_even_when_every_host_fails(tmp_path, monkeypatch):
    """Losing the address because the cleanup failed would be the worse bug."""
    monkeypatch.setattr(
        nightly, "execute", stub_execute({}, raise_for=("i-1",))
    )
    store = tmp_path / "a.json"

    report = run_nightly(["i-1"], "ap-northeast-1", address="203.0.113.10", store=store)

    assert report.instances[0].error == "ssm is down"
    assert nightly.History.load(store).addresses == ["203.0.113.10"]


def test_eviction_is_announced(tmp_path, monkeypatch):
    monkeypatch.setattr(nightly, "execute", stub_execute({}))
    store = tmp_path / "a.json"
    nightly.History(addresses=["a", "b", "c"], keep=3).save(store)

    report = run_nightly(["i-1"], "ap-northeast-1", address="d", keep=3, store=store)

    assert report.evicted == ["a"]
    assert report.window == ["b", "c", "d"]


def test_keep_journals_is_the_default(tmp_path, monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(
        nightly,
        "execute",
        lambda instance, region, addresses, *, apply, extra_flags=None, **_kw: (
            seen.update(extra_flags=extra_flags)
            or nightly.RemoteResult(instance, "c", "Success", "{}", payload=fake_payload())
        ),
    )

    run_nightly(["i-1"], "ap-northeast-1", address="203.0.113.10", store=tmp_path / "a.json")

    assert seen["extra_flags"] == ["--keep-journals"]


def test_delete_journals_sends_no_flag(tmp_path, monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(
        nightly,
        "execute",
        lambda instance, region, addresses, *, apply, extra_flags=None, **_kw: (
            seen.update(extra_flags=extra_flags)
            or nightly.RemoteResult(instance, "c", "Success", "{}", payload=fake_payload())
        ),
    )

    run_nightly(
        ["i-1"],
        "ap-northeast-1",
        address="203.0.113.10",
        keep_journals=False,
        store=tmp_path / "a.json",
    )

    assert seen["extra_flags"] is None


def test_fetch_ignores_the_system_proxy(monkeypatch):
    """The proxied answer is the exit node's address, not this machine's."""
    seen = {}
    real_build = nightly.urllib.request.build_opener

    class FakeResponse:
        def read(self, _limit):
            return b"203.0.113.10\n"

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class FakeOpener:
        def open(self, request, timeout=None):
            return FakeResponse()

    def fake_build_opener(*handlers):
        for handler in handlers:
            if isinstance(handler, nightly.urllib.request.ProxyHandler):
                seen["proxies"] = handler.proxies
        return FakeOpener()

    monkeypatch.setattr(nightly.urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7890")

    assert nightly._fetch_text("https://v4.test") == "203.0.113.10"
    assert seen["proxies"] == {}


def test_discovery_rejects_an_endpoint_that_only_yields_ipv6(monkeypatch):
    bodies = {"https://v6.test": "2001:db8::1", "https://v4.test": "203.0.113.10"}

    def fake_fetch(url):
        return bodies[url]

    monkeypatch.setattr(nightly, "_fetch_text", fake_fetch)

    assert nightly.discover_address(("https://v6.test", "https://v4.test")) == "203.0.113.10"


def test_discovery_failure_lists_what_went_wrong(monkeypatch):
    def fake_fetch(url):
        raise OSError("connection refused")

    monkeypatch.setattr(nightly, "_fetch_text", fake_fetch)

    with pytest.raises(NightlyError) as info:
        nightly.discover_address(("https://a.test", "https://b.test"))

    assert "connection refused" in str(info.value)
    assert "https://a.test" in str(info.value)


def test_empty_report_is_clean_rather_than_vacuously_dirty():
    report = NightlyReport(address="203.0.113.10", window=["203.0.113.10"])

    assert report.clean is True
    assert "found 0 in 0 files" in report.headline()


def test_write_latest_keeps_one_readable_file(tmp_path, monkeypatch):
    monkeypatch.setattr(nightly, "execute", stub_execute({"i-1": fake_payload()}))
    state = tmp_path / "state"
    report = run_nightly(
        ["i-1"], "ap-northeast-1", address="203.0.113.10", store=state / "addresses.json"
    )

    report.started_at = datetime(2026, 11, 25, 16, 0, tzinfo=timezone.utc)
    path = nightly.write_latest(state / "latest.txt", report)
    text = path.read_text(encoding="utf-8")

    assert "2026-11-25 16:00 UTC" in text
    assert "found 868 in 4 files" in text
    assert "i-1" in text


def test_history_log_accumulates_one_line_per_night(tmp_path, monkeypatch):
    monkeypatch.setattr(nightly, "execute", stub_execute({"i-1": fake_payload()}))
    state = tmp_path / "state"
    log = state / "history.log"

    for _ in range(2):
        report = run_nightly(
            ["i-1"], "ap-northeast-1", address="203.0.113.10", store=state / "addresses.json"
        )
        nightly.append_line(log, report.headline())

    lines = log.read_text(encoding="utf-8").strip().splitlines()

    assert len(lines) == 2
    assert all("found" in line for line in lines)

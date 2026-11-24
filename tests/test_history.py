"""The rolling address window."""

from __future__ import annotations

import json

import pytest

from ipscrub.history import DEFAULT_KEEP, History, HistoryError


def test_starts_empty_when_the_file_is_absent(tmp_path):
    history = History.load(tmp_path / "missing.json")

    assert history.addresses == []
    assert len(history) == 0


def test_add_returns_true_only_for_a_new_address():
    history = History(keep=5)

    assert history.add("203.0.113.10") is True
    assert history.add("203.0.113.10") is False
    assert history.addresses == ["203.0.113.10"]


def test_repeating_an_address_moves_it_to_the_warm_end():
    history = History(addresses=["a", "b", "c"], keep=5)

    history.add("a")

    assert history.addresses == ["b", "c", "a"]


def test_window_drops_the_oldest_when_full():
    history = History(addresses=["a", "b", "c"], keep=3)

    history.add("d")

    assert history.addresses == ["b", "c", "d"]


def test_evicted_by_warns_before_the_address_is_added():
    history = History(addresses=["a", "b", "c"], keep=3)

    assert history.evicted_by("d") == ["a"]
    assert history.evicted_by("a") == []
    # The prediction must not change the thing it predicts.
    assert history.addresses == ["a", "b", "c"]


def test_keep_of_one_still_keeps_one():
    history = History(keep=1)

    history.add("a")
    history.add("b")

    assert history.addresses == ["b"]


def test_save_then_load_round_trips(tmp_path):
    path = tmp_path / "state" / "addresses.json"
    history = History(addresses=["a", "b"], keep=4)

    history.save(path)
    reloaded = History.load(path)

    assert reloaded.addresses == ["a", "b"]
    assert reloaded.keep == 4


def test_load_accepts_a_bare_list(tmp_path):
    path = tmp_path / "addresses.json"
    path.write_text(json.dumps(["a", "b"]), encoding="utf-8")

    history = History.load(path, keep=7)

    assert history.addresses == ["a", "b"]
    assert history.keep == 7


def test_save_is_atomic_leaving_no_temp_file(tmp_path):
    path = tmp_path / "addresses.json"
    History(addresses=["a"]).save(path)

    assert path.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_corrupt_file_is_reported_not_silently_reset(tmp_path):
    path = tmp_path / "addresses.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(HistoryError):
        History.load(path)


def test_non_string_entries_are_rejected(tmp_path):
    path = tmp_path / "addresses.json"
    path.write_text(json.dumps({"addresses": [1, 2]}), encoding="utf-8")

    with pytest.raises(HistoryError):
        History.load(path)


def test_default_keep_is_five():
    assert DEFAULT_KEEP == 5

"""End-to-end behaviour against a real temporary directory tree."""

from __future__ import annotations

import base64
import os
from dataclasses import replace

import pytest

from ipscrub.addresses import FULL_REDACTION, PREFIX_REDACTION, Matcher
from ipscrub.plan import Action, Plan, Special
from ipscrub.runner import run

ADDRESS = "203.0.113.9"


def plan_for(root, **overrides):
    """A plan that only looks at *root*, with the host-specific rules trimmed."""
    base = replace(
        Plan(),
        roots=(str(root),),
        specials=(),
        inplace_prefixes=(),
        manage_journald=False,
    )
    return replace(base, **overrides) if overrides else base


def matcher(**kwargs):
    return Matcher.build([ADDRESS], **kwargs)


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    return path


class TestScanOnly:
    def test_finds_and_changes_nothing(self, tmp_path):
        target = write(tmp_path / "syslog", f"node using {ADDRESS}:41641\n")
        outcome = run(matcher(), plan_for(tmp_path), apply=False)
        assert outcome.report.dirty_files == 1
        assert outcome.report.occurrences == 1
        assert ADDRESS in target.read_text()

    def test_clean_tree_reports_nothing(self, tmp_path):
        write(tmp_path / "app.log", "nothing to see here\n")
        outcome = run(matcher(), plan_for(tmp_path), apply=False)
        assert outcome.report.findings == []

    def test_nested_directories_are_walked(self, tmp_path):
        write(tmp_path / "a" / "b" / "c.log", f"peer {ADDRESS}\n")
        outcome = run(matcher(), plan_for(tmp_path), apply=False)
        assert outcome.report.dirty_files == 1

    def test_oversized_file_is_skipped_not_read(self, tmp_path):
        big = write(tmp_path / "huge.bin", os.urandom(4096))
        plan = plan_for(tmp_path, max_bytes=1024)
        outcome = run(matcher(), plan, apply=False)
        assert str(big) in outcome.report.skipped_large
        assert outcome.report.findings == []


class TestClean:
    def test_rewrites_matching_file(self, tmp_path):
        target = write(tmp_path / "syslog", f"using {ADDRESS}\n")
        outcome = run(matcher(), plan_for(tmp_path), apply=True)
        assert outcome.clean
        text = target.read_text()
        assert ADDRESS not in text
        assert FULL_REDACTION.decode() in text

    def test_prefix_is_also_removed(self, tmp_path):
        target = write(tmp_path / "syslog", "peer 203.0.113.250\n")
        run(matcher(), plan_for(tmp_path), apply=True)
        text = target.read_text()
        assert "203.0.113.250" not in text
        assert PREFIX_REDACTION.decode() in text

    def test_keeps_surrounding_content_and_line_count(self, tmp_path):
        body = "\n".join(
            ["line one", f"node using {ADDRESS}:41641 mtu=1360", "line three", ""]
        )
        target = write(tmp_path / "syslog", body)
        run(matcher(), plan_for(tmp_path), apply=True)
        raw = target.read_text()
        assert raw.count("\n") == 3, "line structure must survive the rewrite"
        lines = raw.splitlines()
        assert len(lines) == 3
        assert lines[0] == "line one"
        assert lines[2] == "line three"
        assert "mtu=1360" in lines[1]

    def test_residual_is_empty_after_clean(self, tmp_path):
        write(tmp_path / "a.log", f"{ADDRESS} {ADDRESS}\n")
        outcome = run(matcher(), plan_for(tmp_path), apply=True)
        assert outcome.report.residual == []
        assert outcome.clean

    def test_verification_is_a_real_rescan(self, tmp_path, monkeypatch):
        """If a rewrite silently does nothing, the verdict must catch it."""
        write(tmp_path / "a.log", f"{ADDRESS}\n")
        import ipscrub.runner as runner_module

        monkeypatch.setattr(runner_module, "apply_finding", lambda finding, matcher: finding)
        outcome = run(matcher(), plan_for(tmp_path), apply=True)
        assert outcome.report.residual, "a no-op rewrite must not be reported as clean"
        assert not outcome.clean

    def test_second_run_finds_nothing(self, tmp_path):
        write(tmp_path / "a.log", f"{ADDRESS}\n")
        run(matcher(), plan_for(tmp_path), apply=True)
        again = run(matcher(), plan_for(tmp_path), apply=False)
        assert again.report.findings == []

    def test_binary_file_is_rewritten_safely(self, tmp_path):
        payload = b"\x00\x01\x02" + ADDRESS.encode() + b"\xff\xfe"
        target = write(tmp_path / "blob.bin", payload)
        run(matcher(), plan_for(tmp_path), apply=True)
        data = target.read_bytes()
        assert ADDRESS.encode() not in data
        assert data.startswith(b"\x00\x01\x02")
        assert data.endswith(b"\xff\xfe")

    def test_inplace_action_keeps_inode(self, tmp_path):
        target = write(tmp_path / "appended.log", f"x {ADDRESS}\n")
        before = os.stat(target).st_ino
        plan = plan_for(tmp_path, inplace_prefixes=(str(tmp_path) + os.sep,))
        outcome = run(matcher(), plan, apply=True)
        assert outcome.clean
        assert os.stat(target).st_ino == before, "append-held log must keep its inode"

    def test_atomic_action_changes_inode(self, tmp_path):
        target = write(tmp_path / "plain.log", f"x {ADDRESS}\n")
        before = os.stat(target).st_ino
        run(matcher(), plan_for(tmp_path), apply=True)
        assert os.stat(target).st_ino != before

    @pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
    def test_permissions_are_preserved(self, tmp_path):
        target = write(tmp_path / "secret.log", f"x {ADDRESS}\n")
        os.chmod(target, 0o640)
        run(matcher(), plan_for(tmp_path), apply=True)
        assert oct(os.stat(target).st_mode & 0o777) == "0o640"

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_unreadable_file_is_skipped_without_aborting(self, tmp_path):
        good = write(tmp_path / "good.log", f"{ADDRESS}\n")
        broken = tmp_path / "dangling.log"
        broken.symlink_to(tmp_path / "missing-target.log")
        outcome = run(matcher(), plan_for(tmp_path), apply=True)
        assert outcome.clean
        assert ADDRESS not in good.read_text()


class TestSpecialRules:
    def test_truncate_rule_empties_instead_of_rewriting(self, tmp_path):
        target = write(tmp_path / "agent.log", f"poll {ADDRESS}\n" * 5)
        plan = plan_for(
            tmp_path,
            specials=(Special(str(tmp_path / "agent.log"), Action.TRUNCATE),),
        )
        outcome = run(matcher(), plan, apply=True)
        assert target.read_bytes() == b""
        assert outcome.clean

    def test_delete_rule_removes_file(self, tmp_path):
        target = write(tmp_path / "system.journal", f"bin {ADDRESS}\n")
        plan = plan_for(
            tmp_path,
            specials=(Special(str(tmp_path / "*.journal"), Action.DELETE),),
        )
        outcome = run(matcher(), plan, apply=True)
        assert not target.exists()
        assert outcome.clean

    def test_delete_tree_rule_removes_directory(self, tmp_path):
        tree = tmp_path / "orchestration" / "abc"
        write(tree / "stdout", f"ran with {ADDRESS}\n")
        plan = plan_for(
            tmp_path,
            specials=(Special(str(tmp_path / "orchestration" / "*"), Action.DELETE_TREE),),
        )
        outcome = run(matcher(), plan, apply=True)
        assert not tree.exists()
        assert outcome.clean

    def test_special_wins_over_generic_walk(self, tmp_path):
        target = write(tmp_path / "agent.log", f"poll {ADDRESS}\n")
        plan = plan_for(
            tmp_path,
            specials=(Special(str(tmp_path / "agent.log"), Action.TRUNCATE),),
        )
        outcome = run(matcher(), plan, apply=True)
        actions = {f.path: f.action for f in outcome.report.findings}
        assert actions[str(target)] is Action.TRUNCATE
        assert len(outcome.report.findings) == 1, "must not be scanned twice"

    def test_always_rule_fires_without_a_match(self, tmp_path):
        target = write(tmp_path / "system.journal", "binary noise, no address\n")
        pattern = str(tmp_path / "*.journal")
        plan = plan_for(tmp_path, specials=(Special(pattern, Action.DELETE, always=True),))
        outcome = run(matcher(), plan, apply=True)
        assert not target.exists()
        assert outcome.clean
        reasons = [f.reason for f in outcome.report.findings]
        assert reasons == ["always-delete"]

    def test_always_rule_is_reported_as_unmeasured(self, tmp_path):
        write(tmp_path / "system.journal", "binary noise\n")
        pattern = str(tmp_path / "*.journal")
        plan = plan_for(tmp_path, specials=(Special(pattern, Action.DELETE, always=True),))
        outcome = run(matcher(), plan, apply=False)
        assert len(outcome.report.unmeasured) == 1
        assert "(always-delete)" in outcome.report.findings[0].as_row()

    def test_keep_journals_requires_a_match(self, tmp_path):
        clean = write(tmp_path / "a.journal", "nothing here\n")
        dirty = write(tmp_path / "b.journal", f"x {ADDRESS}\n")
        pattern = str(tmp_path / "*.journal")
        plan = plan_for(tmp_path, specials=(Special(pattern, Action.DELETE, always=True),))
        plan = plan.with_keep_journals()
        outcome = run(matcher(), plan, apply=True)
        assert clean.exists(), "a journal with no match survives --keep-journals"
        assert not dirty.exists()
        assert len(outcome.report.unmeasured) == 0

    def test_removals_run_last(self, tmp_path):
        tree = tmp_path / "orchestration" / "abc"
        write(tree / "stdout", f"ran with {ADDRESS}\n")
        outside = write(tmp_path / "notes.log", f"also {ADDRESS}\n")
        pattern = str(tmp_path / "orchestration" / "*")
        plan = plan_for(
            tmp_path,
            specials=(Special(pattern, Action.DELETE_TREE),),
        )
        outcome = run(matcher(), plan, apply=True)
        assert not tree.exists()
        assert ADDRESS not in outside.read_text()
        assert outcome.clean, outcome.summary_lines()


class TestPlanDefaults:
    def test_write_action_defaults_to_atomic(self):
        plan = Plan()
        assert plan.write_action("/home/user/notes.txt") is Action.REWRITE_ATOMIC

    def test_var_log_is_inplace_by_default(self):
        plan = Plan()
        assert plan.write_action("/var/log/syslog") is Action.REWRITE_INPLACE

    def test_ssm_agent_log_is_truncated(self):
        plan = Plan()
        special = plan.special_for("/var/log/amazon/ssm/amazon-ssm-agent.log")
        assert special is not None
        assert special.action is Action.TRUNCATE

    def test_journal_is_deleted(self):
        plan = Plan()
        special = plan.special_for("/var/log/journal/abc/system.journal")
        assert special is not None
        assert special.action is Action.DELETE

    def test_orchestration_cache_is_deleted(self):
        plan = Plan()
        special = plan.special_for(
            "/var/lib/amazon/ssm/i-123/document/orchestration/abc/stdout"
        )
        assert special is not None
        assert special.action is Action.DELETE_TREE

    def test_for_roots_keeps_everything_else(self):
        plan = Plan.for_roots(["/tmp/x"])
        assert plan.roots == ("/tmp/x",)
        assert plan.specials

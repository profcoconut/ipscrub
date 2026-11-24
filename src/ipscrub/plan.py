"""What to look at, and what to do differently for special paths.

The defaults encode hard-won operational detail:

* the SSM agent keeps its log file open, so it must be truncated rather than
  replaced or the agent keeps writing to a deleted inode;
* journal files are a binary set with no stable text offsets, so they are
  deleted, and journald is stopped for the delete and started afterwards;
* the agent's own orchestration cache records the command it just ran, so
  anything that writes to a host leaves new needles behind in it;
* log files opened with O_APPEND by a daemon must be rewritten in place,
  because an atomic replace would leave the daemon writing to an unlinked
  inode and silently lose every line until the next rotation.
"""

from __future__ import annotations

import fnmatch
import glob
from dataclasses import dataclass, field, replace
from enum import Enum


class Action(str, Enum):
    REWRITE_ATOMIC = "rewrite-atomic"
    REWRITE_INPLACE = "rewrite-inplace"
    TRUNCATE = "truncate"
    DELETE = "delete"
    DELETE_TREE = "delete-tree"


#: Roots worth walking on a typical Linux host.
#: Where an address realistically ends up: logs, config, home directories, state.
#: ``/usr/local`` is deliberately absent.  It is 260 MB of preinstalled tooling
#: (the bundled AWS CLI alone is most of it), no install tree records a client
#: address, and sweeping it tripled the runtime of a nightly pass for no finding.
DEFAULT_ROOTS: tuple[str, ...] = (
    "/var/log",
    "/etc",
    "/home",
    "/root",
    "/var/lib",
    "/tmp",
    "/opt",
    "/srv",
    "/data",
)

#: Pseudo filesystems and build junk: never useful, occasionally hostile.
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset(
    {"proc", "sys", "dev", "run", "__pycache__", ".git", "node_modules"}
)

#: Files larger than this are skipped and reported, not read into memory.
DEFAULT_MAX_BYTES = 200 * 1024 * 1024

#: Paths whose owner rewrites them by appending; keep the inode alive.
DEFAULT_INPLACE_PREFIXES: tuple[str, ...] = ("/var/log/",)


@dataclass(frozen=True)
class Special:
    """A path pattern handled by a rule instead of the generic walk.

    ``always`` says the rule applies without evidence of a match.  That sounds
    reckless and is exactly right for journal files: journald stores entries in
    compressed, deduplicated objects, so a plaintext search returning nothing is
    not evidence that nothing is there.  Deleting the files is the only way the
    final "clean" verdict means anything.  Journal contents are logs, they are
    rotated by the system anyway, and ``keep_journals`` in the plan (or
    ``--keep-journals`` on the command line) downgrades the rule to
    only-on-a-match instead.
    """

    pattern: str
    action: Action
    always: bool = False

    def expand(self) -> list[str]:
        return sorted(glob.glob(self.pattern))


DEFAULT_SPECIALS: tuple[Special, ...] = (
    Special("/var/log/amazon/ssm/amazon-ssm-agent.log*", Action.TRUNCATE),
    Special("/var/log/journal/*/*.journal", Action.DELETE, always=True),
    Special("/run/log/journal/*/*.journal", Action.DELETE, always=True),
    Special("/var/lib/amazon/ssm/*/document/orchestration/*", Action.DELETE_TREE),
    Special("/var/lib/snapd/amazon-ssm-agent/*/document/orchestration/*", Action.DELETE_TREE),
)


def _keep_match_only(specials: tuple[Special, ...]) -> tuple[Special, ...]:
    return tuple(replace(s, always=False) for s in specials)


@dataclass(frozen=True)
class Plan:
    roots: tuple[str, ...] = DEFAULT_ROOTS
    max_bytes: int = DEFAULT_MAX_BYTES
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS
    specials: tuple[Special, ...] = DEFAULT_SPECIALS
    inplace_prefixes: tuple[str, ...] = DEFAULT_INPLACE_PREFIXES
    manage_journald: bool = True

    @classmethod
    def for_roots(cls, roots: list[str] | tuple[str, ...] | None = None) -> "Plan":
        plan = cls()
        if roots:
            plan = replace(plan, roots=tuple(roots))
        return plan

    def with_keep_journals(self) -> "Plan":
        """Delete a journal file only when a plaintext match was found in it."""
        return replace(self, specials=_keep_match_only(self.specials))

    def special_for(self, path: str) -> Special | None:
        for special in self.specials:
            if fnmatch.fnmatch(path, special.pattern):
                return special
        return None

    def write_action(self, path: str) -> Action:
        for prefix in self.inplace_prefixes:
            if path.startswith(prefix):
                return Action.REWRITE_INPLACE
        return Action.REWRITE_ATOMIC

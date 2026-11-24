"""The short history of addresses this machine has used.

Home connections hand out a new address whenever the carrier feels like it, and
the old one stays on every host it ever reached.  Scoping a nightly run to
"today's address" therefore guarantees that yesterday's address is never cleaned
again.  This module keeps a small rolling window instead: recent addresses stay
in scope, and the oldest drops out once the window is full.

Five is the default because the useful question is "did I look like this in the
last week", not "have I ever looked like this".  Counting is per observation, not
per night: a night that sees the same address twice does not push anything out.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_KEEP = 5


class HistoryError(RuntimeError):
    pass


def default_path() -> Path:
    """Where the history lives, honouring the usual platform conventions."""
    override = os.environ.get("IPSCRUB_HISTORY")
    if override:
        return Path(override)
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base) / "ipscrub" / "addresses.json"
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(root) / "ipscrub" / "addresses.json"
    return Path.home() / ".local" / "state" / "ipscrub" / "addresses.json"


@dataclass
class History:
    """An ordered, de-duplicated window of addresses, newest last."""

    addresses: list[str] = field(default_factory=list)
    keep: int = DEFAULT_KEEP

    @classmethod
    def load(cls, path: Path | None = None, *, keep: int = DEFAULT_KEEP) -> "History":
        path = path or default_path()
        if not path.exists():
            return cls(keep=keep)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise HistoryError(f"cannot read {path}: {exc}") from exc
        # Accept both shapes so a hand-written file is not a crash: a bare list,
        # or the object this class writes.  Anything else is a real error.
        if isinstance(raw, list):
            addresses, stored_keep = raw, keep
        elif isinstance(raw, dict):
            addresses, stored_keep = raw.get("addresses", []), int(raw.get("keep", keep))
        else:
            raise HistoryError(f"{path}: expected a list or an object")
        if not all(isinstance(item, str) for item in addresses):
            raise HistoryError(f"{path}: addresses must be strings")
        return cls(addresses=list(addresses), keep=stored_keep)

    def save(self, path: Path | None = None) -> Path:
        """Write atomically: a half-written history loses every old address."""
        path = path or default_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"keep": self.keep, "addresses": self.addresses}, indent=2
        )
        handle, temp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fp:
                fp.write(payload)
            os.replace(temp_name, path)
        except OSError as exc:
            raise HistoryError(f"cannot write {path}: {exc}") from exc
        return path

    def add(self, address: str) -> bool:
        """Record *address*.  Returns True when it was not already known."""
        if address in self.addresses:
            # Move to the warm end: an address still in use is not old.
            self.addresses.remove(address)
            self.addresses.append(address)
            return False
        self.addresses.append(address)
        overflow = len(self.addresses) - max(1, self.keep)
        if overflow > 0:
            del self.addresses[:overflow]
        return True

    def evicted_by(self, address: str) -> list[str]:
        """What ``add(address)`` would drop.  Empty when it is already known."""
        if address in self.addresses:
            return []
        grown = self.addresses + [address]
        overflow = len(grown) - max(1, self.keep)
        return grown[:overflow] if overflow > 0 else []

    def __len__(self) -> int:
        return len(self.addresses)

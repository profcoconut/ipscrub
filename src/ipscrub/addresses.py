"""Address parsing, matching and redaction.

The whole point of this module is that the address being hunted never has to
appear verbatim in a command line, a config file, or a shell history.  Callers
can hand it base64 text (see :meth:`Matcher.build`), and everything that leaves
the process is either a redaction marker or a count.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

FULL_REDACTION = b"<redacted>"
PREFIX_REDACTION = b"<redacted-prefix>"

#: Default prefix lengths.  A /24 identifies a home broadband connection well
#: enough that "I only removed the exact address" is not a meaningful promise.
DEFAULT_PREFIX_LEN = {4: 24, 6: 64}

_V4_BOUNDARY = (rb"(?<![0-9])", rb"(?![0-9])")
_V6_BOUNDARY = (rb"(?<![0-9A-Fa-f:])", rb"(?![0-9A-Fa-f:])")


class AddressError(ValueError):
    """Raised when an address cannot be parsed."""


def decode_address(text: str, *, encoded: bool = False) -> str:
    """Return a canonical address string.

    ``encoded=True`` means *text* is base64, which is how callers keep the
    address out of ``argv``.
    """
    if encoded:
        try:
            text = base64.b64decode(text, validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise AddressError("address is not valid base64") from exc
    text = text.strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise AddressError(f"not an IP address: {text!r}") from exc


def _variants(address: str) -> list[tuple[str, int]]:
    """Every spelling of *address* worth matching, as (literal, version).

    IPv6 has two common spellings (compressed and exploded) and both show up in
    logs depending on which program wrote them.
    """
    ip = ipaddress.ip_address(address)
    if ip.version == 6:
        return [(str(ip), 6), (ip.exploded, 6)]
    return [(str(ip), 4)]


def _prefix_variants(address: str, prefix_len: int | None) -> list[tuple[str, int]]:
    """The text prefix that covers a whole network.

    A peer in the same /24 is written ``203.0.113.250`` while the network address
    is ``203.0.113.0``, so matching the network address would miss every other
    host.  What actually catches them is the *octet prefix*: ``203.0.113``.

    Only octet-aligned prefixes can be expressed as text, so the prefix length is
    rounded down to a whole number of octets (IPv4) or groups (IPv6).
    """
    if not prefix_len:
        return []
    ip = ipaddress.ip_address(address)
    if ip.version == 6:
        groups = ip.exploded.split(":")
        keep = max(1, prefix_len // 16)
        return [(":".join(groups[:keep]), 6)]
    octets = str(ip).split(".")
    keep = max(1, min(3, prefix_len // 8))
    return [(".".join(octets[:keep]), 4)]


def _compile(literal: str, version: int, *, extend: bool = False) -> re.Pattern[bytes]:
    """Compile a needle.

    ``extend`` makes a prefix match swallow the rest of the address, so
    ``203.0.113`` redacts ``203.0.113.250`` as one token instead of leaving a
    dangling ``.250`` that still describes a peer.
    """
    left, right = _V6_BOUNDARY if version == 6 else _V4_BOUNDARY
    tail = b""
    if extend:
        tail = rb"(?::[0-9A-Fa-f]{0,4})*" if version == 6 else rb"(?:\.[0-9]{1,3})*"
    return re.compile(left + re.escape(literal.encode("ascii")) + tail + right)


@dataclass(frozen=True)
class Matcher:
    """A compiled set of needles plus the redaction routine."""

    addresses: tuple[str, ...]
    prefix_len: int | None
    full: tuple[re.Pattern[bytes], ...]
    prefix: tuple[re.Pattern[bytes], ...]

    # -- construction ----------------------------------------------------
    @classmethod
    def build(
        cls,
        addresses: Iterable[str],
        *,
        prefix_len: int | None = None,
        encode_prefixes: bool = True,
    ) -> "Matcher":
        canonical = []
        for raw in addresses:
            address = decode_address(raw)
            if address not in canonical:
                canonical.append(address)
        if not canonical:
            raise AddressError("no addresses given")

        full_literals: list[tuple[str, int]] = []
        prefix_literals: list[tuple[str, int]] = []
        for address in canonical:
            for literal, version in _variants(address):
                if (literal, version) not in full_literals:
                    full_literals.append((literal, version))
            if encode_prefixes:
                length = prefix_len
                if length is None:
                    length = DEFAULT_PREFIX_LEN[ipaddress.ip_address(address).version]
                for literal, version in _prefix_variants(address, length):
                    if (literal, version) not in prefix_literals:
                        prefix_literals.append((literal, version))

        # Longest first: an exploded IPv6 literal contains its own tail, and a
        # shorter needle matched first would leave debris behind.
        full_literals.sort(key=lambda item: len(item[0]), reverse=True)
        prefix_literals.sort(key=lambda item: len(item[0]), reverse=True)

        return cls(
            addresses=tuple(canonical),
            prefix_len=prefix_len,
            full=tuple(_compile(lit, ver) for lit, ver in full_literals),
            prefix=tuple(_compile(lit, ver, extend=True) for lit, ver in prefix_literals),
        )

    # -- measurement -----------------------------------------------------
    def count(self, blob: bytes) -> tuple[int, int]:
        """Return ``(full_matches, prefix_only_matches)``."""
        full = sum(len(pattern.findall(blob)) for pattern in self.full)
        pref = 0
        if self.prefix:
            # Full addresses are counted first; a prefix hit inside one of them
            # is not a separate leak, so remove them before counting prefixes.
            stripped = self._strip_full(blob)
            pref = sum(len(pattern.findall(stripped)) for pattern in self.prefix)
        return full, pref

    def _strip_full(self, blob: bytes) -> bytes:
        for pattern in self.full:
            blob = pattern.sub(b"", blob)
        return blob

    # -- redaction -------------------------------------------------------
    def redact(self, blob: bytes) -> bytes:
        for pattern in self.full:
            blob = pattern.sub(FULL_REDACTION, blob)
        for pattern in self.prefix:
            blob = pattern.sub(PREFIX_REDACTION, blob)
        return blob

    def describe(self) -> str:
        """A report-safe description: the network, never the exact host address."""
        parts = []
        for address in self.addresses:
            ip = ipaddress.ip_address(address)
            length = self.prefix_len or DEFAULT_PREFIX_LEN[ip.version]
            parts.append(str(ipaddress.ip_network(f"{ip}/{length}", strict=False)))
        return ", ".join(parts)

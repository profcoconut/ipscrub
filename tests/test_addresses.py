"""Address matching and redaction."""

from __future__ import annotations

import base64

import pytest

from ipscrub.addresses import (
    FULL_REDACTION,
    PREFIX_REDACTION,
    AddressError,
    Matcher,
    decode_address,
)


class TestDecode:
    def test_plain(self):
        assert decode_address("203.0.113.9") == "203.0.113.9"

    def test_encoded(self):
        assert decode_address("MjAzLjAuMTEzLjk=", encoded=True) == "203.0.113.9"

    def test_encoded_keeps_address_out_of_text(self):
        encoded = base64.b64encode(b"198.51.100.7").decode()
        assert "198.51.100.7" not in encoded

    def test_rejects_garbage(self):
        with pytest.raises(AddressError):
            decode_address("not-an-ip")

    def test_rejects_bad_base64(self):
        with pytest.raises(AddressError):
            decode_address("!!!!", encoded=True)

    def test_ipv6_compressed(self):
        assert decode_address("2001:db8::1") == "2001:db8::1"


class TestCount:
    def test_counts_exact_address(self):
        matcher = Matcher.build(["203.0.113.9"], encode_prefixes=False)
        assert matcher.count(b"a 203.0.113.9 b 203.0.113.9") == (2, 0)

    def test_no_false_positive_on_neighbour_octet(self):
        matcher = Matcher.build(["203.0.113.9"], encode_prefixes=False)
        assert matcher.count(b"203.0.113.99 and 203.0.113.9") == (1, 0)

    def test_prefix_counts_only_other_hosts_in_network(self):
        matcher = Matcher.build(["203.0.113.9"])
        # .9 is the exact address, .250 is a different host in the same /24
        blob = b"me 203.0.113.9 peer 203.0.113.250"
        full, prefix = matcher.count(blob)
        assert full == 1
        assert prefix == 1

    def test_prefix_not_double_counted(self):
        matcher = Matcher.build(["203.0.113.9"])
        assert matcher.count(b"only 203.0.113.9 here") == (1, 0)

    def test_disabled_prefix(self):
        matcher = Matcher.build(["203.0.113.9"], prefix_len=0, encode_prefixes=False)
        assert matcher.count(b"203.0.113.9 203.0.113.250") == (1, 0)

    def test_custom_prefix_length(self):
        matcher = Matcher.build(["203.0.113.9"], prefix_len=16)
        full, prefix = matcher.count(b"203.0.113.9 203.0.140.5")
        assert (full, prefix) == (1, 1)

    def test_ipv6_matches_exploded_spelling(self):
        matcher = Matcher.build(["2001:db8::1"], encode_prefixes=False)
        exploded = b"2001:0db8:0000:0000:0000:0000:0000:0001"
        assert matcher.count(exploded)[0] == 1

    def test_empty_input_rejected(self):
        with pytest.raises(AddressError):
            Matcher.build([])


class TestRedact:
    def test_replaces_exact(self):
        matcher = Matcher.build(["203.0.113.9"], encode_prefixes=False)
        assert matcher.redact(b"from 203.0.113.9") == b"from " + FULL_REDACTION

    def test_replaces_prefix(self):
        matcher = Matcher.build(["203.0.113.9"])
        cleaned = matcher.redact(b"peer 203.0.113.250")
        assert cleaned == b"peer " + PREFIX_REDACTION

    def test_prefix_redaction_leaves_no_octets_behind(self):
        matcher = Matcher.build(["203.0.113.9"])
        cleaned = matcher.redact(b"from 203.0.113.250 port")
        assert b"203.0.113" not in cleaned
        assert b".250" not in cleaned

    def test_leaves_unrelated_text(self):
        matcher = Matcher.build(["203.0.113.9"])
        blob = b"tailscaled: node now using 203.0.113.9:41641 mtu=1360"
        cleaned = matcher.redact(blob)
        assert FULL_REDACTION in cleaned
        assert b"41641 mtu=1360" in cleaned

    def test_idempotent(self):
        matcher = Matcher.build(["203.0.113.9"])
        once = matcher.redact(b"x 203.0.113.9 y 203.0.113.250")
        assert matcher.redact(once) == once

    def test_describe_hides_host_bits(self):
        matcher = Matcher.build(["203.0.113.9"])
        described = matcher.describe()
        assert "203.0.113.0/24" in described
        assert "203.0.113.9" not in described

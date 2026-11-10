"""Pattern matching and edge cases for sanitize_text."""

import pytest

from log_sanitizer import Whitelist, sanitize_text


def redact(text, *allow):
    return sanitize_text(text, Whitelist(allow))


# --- emails -----------------------------------------------------------------

@pytest.mark.parametrize("email", [
    "user@example.com",
    "first.last+tag@sub.example.org",
    "a_b-c%d@example.co.uk",
])
def test_redacts_emails(email):
    out, counts = redact(f"login by {email} ok")
    assert out == "login by [REDACTED_EMAIL] ok"
    assert counts == {"email": 1}


@pytest.mark.parametrize("text", ["user@localhost", "@example.com", "user@.com", "a @ b.com"])
def test_ignores_non_emails(text):
    out, counts = redact(text)
    assert out == text
    assert not counts


def test_email_followed_by_punctuation():
    out, _ = redact("contact <user@example.com>, then user@example.com.")
    assert out == "contact <[REDACTED_EMAIL]>, then [REDACTED_EMAIL]."


# --- IPv4 -------------------------------------------------------------------

@pytest.mark.parametrize("ip", ["192.0.2.1", "0.0.0.0", "255.255.255.255", "10.0.0.254"])
def test_redacts_ipv4(ip):
    out, counts = redact(f"from {ip}:8080 ok")
    assert out == "from [REDACTED_IPV4]:8080 ok"
    assert counts == {"ipv4": 1}


@pytest.mark.parametrize("text", [
    "256.1.1.1",
    "1.2.3",
    "version 1.2.3.4.5",
    "build 192.0.2.1a",
    "v10.0.0.1",
])
def test_ignores_non_ipv4(text):
    out, counts = redact(text)
    assert out == text
    assert not counts


def test_ipv4_at_end_of_sentence():
    out, _ = redact("blocked 198.51.100.7.")
    assert out == "blocked [REDACTED_IPV4]."


# --- IPv6 -------------------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "2001:db8::1",
    "2001:0db8:0000:0000:0000:ff00:0042:8329",
    "fe80::1ff:fe23:4567:890a",
    "::1",
    "::ffff:192.0.2.128",
])
def test_redacts_ipv6(ip):
    out, counts = redact(f"peer [{ip}] connected")
    assert out == "peer [[REDACTED_IPV6]] connected"
    assert counts == {"ipv6": 1}


@pytest.mark.parametrize("text", [
    "at 12:34:56 started",
    "mac 00:1a:2b:3c:4d:5e",
    "ratio 1:2",
    "std::vector",
])
def test_ignores_ipv6_lookalikes(text):
    out, counts = redact(text)
    assert out == text
    assert not counts


# --- secrets ----------------------------------------------------------------

@pytest.mark.parametrize("line, expected", [
    ("api_key=abc123def456", "api_key=[REDACTED_SECRET]"),
    ("API-KEY: abc123def456", "API-KEY: [REDACTED_SECRET]"),
    ('"password": "hunter22"', '"password": "[REDACTED_SECRET]"'),
    ("token='q1w2e3r4t5'", "token='[REDACTED_SECRET]'"),
    ("url?access_token=zzzzzz9&x=1", "url?access_token=[REDACTED_SECRET]&x=1"),
])
def test_redacts_secret_assignments(line, expected):
    out, counts = redact(line)
    assert out == expected
    assert counts == {"secret": 1}


def test_short_values_are_not_treated_as_secrets():
    out, counts = redact("password=abc token: no")
    assert out == "password=abc token: no"
    assert not counts


def test_redacts_bearer_token():
    out, counts = redact("Authorization: Bearer abc.DEF-123_xyz==")
    assert out == "Authorization: Bearer [REDACTED_SECRET]"
    assert counts == {"secret": 1}


@pytest.mark.parametrize("token", [
    "AKIA" + "IOSFODNN7EXAMPLE",
    "ghp_" + "x" * 36,
    "sk_" + "test_" + "a" * 24,
    "xoxb-" + "1234-abcd-5678",
])
def test_redacts_prefixed_tokens(token):
    out, counts = redact(f"using {token} now")
    assert out == "using [REDACTED_SECRET] now"
    assert counts == {"secret": 1}


def test_redacts_long_generic_token():
    token = "a1B2c3D4" * 5
    out, counts = redact(f"session {token} issued")
    assert out == "session [REDACTED_SECRET] issued"
    assert counts == {"secret": 1}


@pytest.mark.parametrize("text", [
    "a" * 40,  # no digits
    "1" * 40,  # no letters
    "123e4567-e89b-12d3-a456-426614174000",  # UUID request ids stay readable
    "short1abc",
])
def test_ignores_non_generic_tokens(text):
    out, counts = redact(text)
    assert out == text
    assert not counts


def test_email_inside_secret_assignment_counted_once():
    out, counts = redact("password=user@example.com")
    assert out == "password=[REDACTED_EMAIL]"
    assert counts == {"email": 1}


# --- whitelist --------------------------------------------------------------

def test_whitelisted_terms_are_kept():
    text = "from 192.0.2.1 and 192.0.2.2 by ops@example.com"
    out, counts = redact(text, "192.0.2.1", "OPS@EXAMPLE.COM")
    assert out == "from 192.0.2.1 and [REDACTED_IPV4] by ops@example.com"
    assert counts == {"ipv4": 1}


def test_whitelist_cidr_ranges():
    text = "10.1.2.3 10.255.0.1 192.0.2.9 2001:db8::5 2001:db9::5"
    out, counts = redact(text, "10.0.0.0/8", "2001:db8::/32")
    assert out == "10.1.2.3 10.255.0.1 [REDACTED_IPV4] 2001:db8::5 [REDACTED_IPV6]"
    assert counts == {"ipv4": 1, "ipv6": 1}


def test_whitelisted_secret_value():
    out, counts = redact("token=placeholder", "placeholder")
    assert out == "token=placeholder"
    assert not counts


def test_whitelist_ignores_blank_and_invalid_cidr():
    whitelist = Whitelist(["", "   ", "not/a/network"])
    assert len(whitelist) == 1
    assert "not/a/network" in whitelist
    assert "192.0.2.1" not in whitelist


# --- general ----------------------------------------------------------------

def test_empty_and_clean_text():
    assert redact("") == ("", {})
    assert redact("nothing to see here\n") == ("nothing to see here\n", {})


def test_mixed_line_counts_each_kind():
    line = "2026-01-01 12:00:00 user@example.com from 192.0.2.1 / 2001:db8::1 api_key=abcdef123456"
    out, counts = redact(line)
    assert out == (
        "2026-01-01 12:00:00 [REDACTED_EMAIL] from [REDACTED_IPV4] / "
        "[REDACTED_IPV6] api_key=[REDACTED_SECRET]"
    )
    assert counts == {"email": 1, "ipv4": 1, "ipv6": 1, "secret": 1}


def test_sanitizing_is_idempotent():
    once, _ = redact("user@example.com 192.0.2.1 token=abcdef123")
    twice, counts = redact(once)
    assert twice == once
    assert not counts

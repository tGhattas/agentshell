"""Tests for the authentication module."""

import pyotp

from agentshell.auth import (
    constant_time_compare,
    generate_session_token,
    generate_totp_secret,
    hash_password,
    verify_password,
    verify_totp,
)


def test_password_hash_and_verify():
    pw_hash = hash_password("correct-horse-battery-staple")
    assert verify_password(pw_hash, "correct-horse-battery-staple")
    assert not verify_password(pw_hash, "wrong-password")


def test_password_hash_is_unique():
    h1 = hash_password("same-password")
    h2 = hash_password("same-password")
    assert h1 != h2  # Different salts


def test_totp_verify():
    secret = generate_totp_secret()
    totp = pyotp.TOTP(secret)
    code = totp.now()
    assert verify_totp(secret, code)
    assert not verify_totp(secret, "000000")


def test_session_token_uniqueness():
    t1 = generate_session_token()
    t2 = generate_session_token()
    assert t1 != t2
    assert len(t1) > 32


def test_constant_time_compare():
    assert constant_time_compare("abc", "abc")
    assert not constant_time_compare("abc", "def")

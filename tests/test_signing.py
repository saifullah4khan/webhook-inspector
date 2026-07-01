"""Tests for the HMAC signing and verification helpers."""

from __future__ import annotations

import pytest

from webhook_inspector import sign, verify

SECRET = "topsecret"
BODY = b'{"event":"thing.created","id":42}'


def test_sign_has_algorithm_prefix():
    signature = sign(BODY, SECRET)
    assert signature.startswith("sha256=")
    assert len(signature.split("=", 1)[1]) == 64  # sha256 hex digest length


def test_verify_accepts_a_matching_signature():
    signature = sign(BODY, SECRET)
    assert verify(BODY, SECRET, signature) is True


def test_verify_rejects_a_tampered_body():
    signature = sign(BODY, SECRET)
    assert verify(BODY + b" ", SECRET, signature) is False


def test_verify_rejects_the_wrong_secret():
    signature = sign(BODY, "a-different-secret")
    assert verify(BODY, SECRET, signature) is False


def test_verify_rejects_empty_or_missing_header():
    assert verify(BODY, SECRET, "") is False
    assert verify(BODY, SECRET, None) is False


def test_verify_returns_false_without_raising_on_garbage():
    assert verify(BODY, SECRET, "not-even-a-signature") is False


def test_sign_requires_a_secret():
    with pytest.raises(ValueError):
        sign(BODY, "")


def test_unsupported_algorithm_is_rejected():
    with pytest.raises(ValueError):
        sign(BODY, SECRET, algorithm="md5")
    # verify degrades to False rather than raising.
    assert verify(BODY, SECRET, "md5=abc", algorithm="md5") is False


def test_sha512_round_trip():
    signature = sign(BODY, SECRET, algorithm="sha512")
    assert signature.startswith("sha512=")
    assert verify(BODY, SECRET, signature, algorithm="sha512") is True

"""HMAC signing and constant-time verification for webhook payloads.

The signature format is ``<algorithm>=<hexdigest>`` (for example
``sha256=9f86d0...``), the same convention used by GitHub, Stripe, and most
providers. Signing and verifying share one code path so a payload signed here
verifies here, which is what makes replay safe.
"""

from __future__ import annotations

import hashlib
import hmac

DEFAULT_ALGORITHM = "sha256"

# Algorithms we are willing to use. Restricting the set keeps a caller from
# accidentally selecting a weak or non-existent hash by passing a stray string.
_SUPPORTED_ALGORITHMS = frozenset({"sha1", "sha256", "sha512"})


def sign(body: bytes, secret: str, *, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return the ``<algorithm>=<hexdigest>`` HMAC signature of *body*.

    :param body: The exact raw request body bytes that will be transmitted.
        Sign the bytes, never a re-serialized dict - any whitespace or key
        ordering difference changes the digest and breaks verification.
    :param secret: The shared signing secret.
    :param algorithm: One of ``sha1``, ``sha256`` (default), or ``sha512``.
    """
    if algorithm not in _SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm!r}")
    if not secret:
        raise ValueError("A non-empty signing secret is required.")
    digest = hmac.new(secret.encode(), body, getattr(hashlib, algorithm)).hexdigest()
    return f"{algorithm}={digest}"


def verify(
    body: bytes,
    secret: str,
    signature_header: str,
    *,
    algorithm: str = DEFAULT_ALGORITHM,
) -> bool:
    """Return ``True`` when *signature_header* is a valid signature of *body*.

    The comparison uses :func:`hmac.compare_digest`, which runs in constant
    time with respect to the number of matching leading characters. A naive
    ``==`` leaks, through its timing, how much of a forged signature was
    correct, which is enough for an attacker to reconstruct a valid one byte
    by byte. Any malformed or missing input returns ``False`` rather than
    raising, so a bad header can never crash the receiver.
    """
    if not signature_header or not secret:
        return False
    if algorithm not in _SUPPORTED_ALGORITHMS:
        return False
    expected = sign(body, secret, algorithm=algorithm)
    return hmac.compare_digest(expected, signature_header)

"""webhook-inspector: receive, verify, inspect, and replay webhooks.

A small Flask service for anyone integrating a webhook provider. It captures
incoming deliveries, verifies their HMAC signature in constant time, keeps the
recent ones in a bounded in-memory buffer, and can re-sign and replay a
captured delivery to any target URL.
"""

from __future__ import annotations

from .app import create_app
from .signing import DEFAULT_ALGORITHM, sign, verify
from .store import CaptureStore

__all__ = ["create_app", "sign", "verify", "CaptureStore", "DEFAULT_ALGORITHM"]

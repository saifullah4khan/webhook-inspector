"""In-memory ring buffer of captured webhook deliveries.

An inspector should never fall over because it received a lot of traffic, and
it should never need a database to be useful. The store keeps the most recent
*maxlen* deliveries and drops the oldest automatically, so memory stays bounded
no matter how long the process runs.
"""

from __future__ import annotations

import itertools
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Optional


class CaptureStore:
    """Thread-safe, bounded collection of captured deliveries.

    Flask serves requests from multiple threads by default, so every mutation
    is guarded by a lock. Each captured delivery gets a monotonic integer id
    that stays stable for the lifetime of the process, which is what the
    replay endpoint refers to.
    """

    def __init__(self, maxlen: int = 100) -> None:
        if maxlen < 1:
            raise ValueError("maxlen must be at least 1")
        self._deliveries: deque[dict] = deque(maxlen=maxlen)
        self._counter = itertools.count(1)
        self._lock = threading.Lock()

    def add(
        self,
        *,
        method: str,
        path: str,
        headers: dict,
        body: bytes,
        signature_valid: Optional[bool],
    ) -> dict:
        """Record one delivery and return the stored representation."""
        record = {
            "id": next(self._counter),
            "received_at": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": path,
            "headers": dict(headers),
            # Store the decoded body for display; replace undecodable bytes so
            # arbitrary payloads never raise on capture.
            "body": body.decode("utf-8", errors="replace"),
            "signature_valid": signature_valid,
        }
        with self._lock:
            self._deliveries.append(record)
        return record

    def list(self) -> list[dict]:
        """Return all captured deliveries, newest first."""
        with self._lock:
            return list(reversed(self._deliveries))

    def get(self, delivery_id: int) -> Optional[dict]:
        """Return the delivery with *delivery_id*, or ``None`` if evicted."""
        with self._lock:
            for record in self._deliveries:
                if record["id"] == delivery_id:
                    return record
        return None

    def clear(self) -> None:
        """Drop all captured deliveries (the id counter keeps advancing)."""
        with self._lock:
            self._deliveries.clear()

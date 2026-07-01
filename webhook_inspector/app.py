"""Flask application factory for the webhook inspector.

Endpoints:

* ``POST /webhook``           - capture any incoming webhook, verify its
                                signature if a secret is configured.
* ``GET  /captures``          - list captured deliveries, newest first.
* ``GET  /captures/<id>``     - fetch one captured delivery.
* ``DELETE /captures``        - clear the buffer.
* ``POST /replay/<id>``       - re-sign a captured body and forward it to a
                                target URL you supply.

The app is built by :func:`create_app` so tests can inject a fake HTTP poster
and their own store, and so configuration comes from arguments or environment
variables rather than module-level globals.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

import requests
from flask import Flask, jsonify, request

from .signing import DEFAULT_ALGORITHM, sign, verify
from .store import CaptureStore

# A poster takes (url, data, headers) and returns an object exposing
# .status_code. requests.post satisfies this; tests pass a fake.
Poster = Callable[..., object]


def _default_poster(url: str, *, data: bytes, headers: dict):
    return requests.post(url, data=data, headers=headers, timeout=5)


def create_app(
    *,
    secret: Optional[str] = None,
    signature_header: str = "X-Signature",
    algorithm: str = DEFAULT_ALGORITHM,
    capture_limit: int = 100,
    store: Optional[CaptureStore] = None,
    poster: Optional[Poster] = None,
) -> Flask:
    """Build and return the inspector Flask app.

    :param secret: Shared secret used to verify incoming signatures and to
        re-sign replays. When ``None`` (or empty), verification is skipped and
        captured deliveries are marked with ``signature_valid: null``.
    :param signature_header: Request header carrying the ``algo=hexdigest``
        signature. Defaults to ``X-Signature``.
    :param algorithm: HMAC algorithm for verify and replay.
    :param capture_limit: Max deliveries retained in the ring buffer.
    :param store: Optional pre-built :class:`CaptureStore` (mainly for tests).
    :param poster: Optional HTTP poster for replay (mainly for tests).
    """
    app = Flask(__name__)
    app.config["INSPECTOR_SECRET"] = secret or os.getenv("WEBHOOK_SECRET") or ""
    app.config["INSPECTOR_SIGNATURE_HEADER"] = signature_header
    app.config["INSPECTOR_ALGORITHM"] = algorithm

    capture_store = store or CaptureStore(maxlen=capture_limit)
    http_post = poster or _default_poster

    @app.post("/webhook")
    def receive():
        raw = request.get_data()  # exact bytes, needed for signature checks
        configured_secret = app.config["INSPECTOR_SECRET"]
        header_name = app.config["INSPECTOR_SIGNATURE_HEADER"]

        if configured_secret:
            provided = request.headers.get(header_name, "")
            signature_valid = verify(
                raw,
                configured_secret,
                provided,
                algorithm=app.config["INSPECTOR_ALGORITHM"],
            )
        else:
            # No secret configured: we still capture, but we can't judge it.
            signature_valid = None

        record = capture_store.add(
            method=request.method,
            path=request.path,
            headers=dict(request.headers),
            body=raw,
            signature_valid=signature_valid,
        )
        return (
            jsonify(
                {
                    "status": "captured",
                    "id": record["id"],
                    "signature_valid": signature_valid,
                }
            ),
            200,
        )

    @app.get("/captures")
    def list_captures():
        return jsonify(capture_store.list()), 200

    @app.get("/captures/<int:delivery_id>")
    def get_capture(delivery_id: int):
        record = capture_store.get(delivery_id)
        if record is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(record), 200

    @app.delete("/captures")
    def clear_captures():
        capture_store.clear()
        return jsonify({"status": "cleared"}), 200

    @app.post("/replay/<int:delivery_id>")
    def replay(delivery_id: int):
        record = capture_store.get(delivery_id)
        if record is None:
            return jsonify({"error": "not found"}), 404

        payload = request.get_json(silent=True) or {}
        target_url = payload.get("target_url")
        if not target_url:
            return jsonify({"error": "target_url is required"}), 400

        body = record["body"].encode("utf-8")
        headers = {"Content-Type": "application/json"}
        configured_secret = app.config["INSPECTOR_SECRET"]
        if configured_secret:
            # Re-sign so the downstream receiver's own verification passes.
            headers[app.config["INSPECTOR_SIGNATURE_HEADER"]] = sign(
                body,
                configured_secret,
                algorithm=app.config["INSPECTOR_ALGORITHM"],
            )

        try:
            response = http_post(target_url, data=body, headers=headers)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the inspector
            return jsonify({"status": "error", "detail": str(exc)}), 502

        return (
            jsonify(
                {
                    "status": "replayed",
                    "target_url": target_url,
                    "response_status": getattr(response, "status_code", None),
                }
            ),
            200,
        )

    return app

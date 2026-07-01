"""Tests for the Flask inspector app, using the test client and a fake poster."""

from __future__ import annotations

import json

import pytest

from webhook_inspector import CaptureStore, create_app, sign

SECRET = "topsecret"
BODY = b'{"event":"thing.created","id":42}'


class FakePoster:
    """Records replay calls and returns a canned status code."""

    def __init__(self, status_code=200):
        self.status_code = status_code
        self.calls = []

    def __call__(self, url, *, data, headers):
        self.calls.append({"url": url, "data": data, "headers": headers})
        return type("Resp", (), {"status_code": self.status_code})()


@pytest.fixture
def poster():
    return FakePoster()


@pytest.fixture
def client(poster):
    app = create_app(secret=SECRET, poster=poster)
    app.testing = True
    return app.test_client()


def test_valid_signature_is_captured_and_marked_valid(client):
    signature = sign(BODY, SECRET)
    resp = client.post("/webhook", data=BODY, headers={"X-Signature": signature})
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["status"] == "captured"
    assert payload["signature_valid"] is True


def test_invalid_signature_is_still_captured_but_flagged(client):
    resp = client.post("/webhook", data=BODY, headers={"X-Signature": "sha256=deadbeef"})
    assert resp.status_code == 200
    assert resp.get_json()["signature_valid"] is False


def test_without_secret_signature_is_unjudged():
    app = create_app(secret=None)
    app.testing = True
    c = app.test_client()
    resp = c.post("/webhook", data=BODY)
    assert resp.status_code == 200
    assert resp.get_json()["signature_valid"] is None


def test_list_and_get_captures(client):
    signature = sign(BODY, SECRET)
    client.post("/webhook", data=BODY, headers={"X-Signature": signature})
    client.post("/webhook", data=BODY, headers={"X-Signature": signature})

    listing = client.get("/captures").get_json()
    assert len(listing) == 2
    # Newest first.
    assert listing[0]["id"] > listing[1]["id"]

    one = client.get(f"/captures/{listing[0]['id']}").get_json()
    assert one["signature_valid"] is True
    assert json.loads(one["body"])["id"] == 42


def test_get_missing_capture_returns_404(client):
    assert client.get("/captures/9999").status_code == 404


def test_clear_empties_the_buffer(client):
    signature = sign(BODY, SECRET)
    client.post("/webhook", data=BODY, headers={"X-Signature": signature})
    assert client.delete("/captures").status_code == 200
    assert client.get("/captures").get_json() == []


def test_replay_resigns_and_forwards(client, poster):
    signature = sign(BODY, SECRET)
    capture_id = client.post(
        "/webhook", data=BODY, headers={"X-Signature": signature}
    ).get_json()["id"]

    resp = client.post(
        f"/replay/{capture_id}",
        data=json.dumps({"target_url": "https://example.test/hook"}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "replayed"
    assert body["response_status"] == 200

    # The forwarded request carried a freshly computed valid signature.
    assert len(poster.calls) == 1
    forwarded = poster.calls[0]
    assert forwarded["url"] == "https://example.test/hook"
    assert forwarded["headers"]["X-Signature"] == sign(BODY, SECRET)


def test_replay_requires_target_url(client):
    signature = sign(BODY, SECRET)
    capture_id = client.post(
        "/webhook", data=BODY, headers={"X-Signature": signature}
    ).get_json()["id"]
    resp = client.post(f"/replay/{capture_id}", json={})
    assert resp.status_code == 400


def test_replay_missing_capture_returns_404(client):
    resp = client.post("/replay/9999", json={"target_url": "https://example.test"})
    assert resp.status_code == 404


def test_store_evicts_oldest_beyond_limit():
    store = CaptureStore(maxlen=2)
    for i in range(3):
        store.add(method="POST", path="/webhook", headers={}, body=str(i).encode(), signature_valid=None)
    listing = store.list()
    assert len(listing) == 2
    bodies = [r["body"] for r in listing]
    assert bodies == ["2", "1"]  # newest first, oldest ("0") evicted

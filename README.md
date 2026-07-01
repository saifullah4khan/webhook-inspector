# webhook-inspector

A tiny Flask service that receives any webhook, verifies its signature, keeps
the recent deliveries around to look at, and can replay them to a target of
your choice.

## The problem

Integrating a webhook provider is mostly a debugging problem. The payload
arrives once, from a server you don't control, and if your handler has a bug
you often can't get the provider to send it again. On top of that, most
providers sign their payloads with an HMAC, and getting that verification
subtly wrong is a real security hole: comparing signatures with a plain `==`
leaks timing information that lets an attacker forge one.

This service sits in front of your integration work. It captures every
delivery so you can inspect the exact bytes and headers, tells you whether the
signature checks out, and lets you replay a captured delivery as many times as
you need while you fix your handler.

## Quickstart

```bash
pip install webhook-inspector
```

```python
from webhook_inspector import create_app

app = create_app(secret="your-provider-signing-secret")

if __name__ == "__main__":
    app.run(port=8000)
```

Point your provider (or a test) at `http://localhost:8000/webhook` and then:

```bash
# See what came in, newest first
curl localhost:8000/captures

# Replay delivery #1 to your real handler
curl -X POST localhost:8000/replay/1 \
  -H 'Content-Type: application/json' \
  -d '{"target_url": "http://localhost:5000/my-real-handler"}'
```

There is also a ready-to-run example that starts the inspector with a demo
secret and prints a signed sample request you can paste into a shell:

```bash
python example.py
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/webhook` | Capture an incoming delivery and verify its signature. |
| `GET` | `/captures` | List captured deliveries, newest first. |
| `GET` | `/captures/<id>` | Fetch one captured delivery. |
| `DELETE` | `/captures` | Clear the buffer. |
| `POST` | `/replay/<id>` | Re-sign a captured body and forward it to `target_url`. |

## Design decisions

**Signatures are compared in constant time.** Verification uses
`hmac.compare_digest`, not `==`. A normal string comparison returns as soon as
two characters differ, so the time it takes reveals how many leading
characters of a guess were correct. That is enough to reconstruct a valid
signature one byte at a time. Constant-time comparison closes that door, and
it is the single most important correctness detail in the whole project.

**The raw request bytes are signed and verified, never a re-parsed body.** A
signature covers exact bytes. If you parse JSON and re-serialize it, key order
or whitespace can change and the digest no longer matches. The receiver reads
`request.get_data()` and the store keeps the original body, so replay sends
back exactly what arrived.

**Replay re-signs with your secret.** A captured body forwarded as-is would
fail your downstream handler's own signature check. Replay computes a fresh
signature with the configured secret before forwarding, so the delivery is
valid at its destination.

**Verification is opt-in.** With no secret configured the service still
captures everything and marks each delivery `signature_valid: null`, which is
useful when you are exploring a provider before you have wired up the secret.
Once a secret is set, deliveries are marked `true` or `false`.

**Storage is a bounded in-memory ring buffer.** An inspector is a debugging
tool, not a system of record, so it keeps only the most recent deliveries
(100 by default) and drops the oldest automatically. There is no database to
run and memory can't grow without bound, even under a flood of traffic.

**The app is built by a factory.** `create_app` takes its secret, header name,
algorithm, buffer size, store, and HTTP poster as arguments. That keeps
configuration explicit and makes the whole thing testable with Flask's test
client and a fake poster, with no network and no global state.

## Configuration

`create_app` arguments (environment variable fallbacks in parentheses):

| Argument | Default | Meaning |
| --- | --- | --- |
| `secret` | `WEBHOOK_SECRET` env, else empty | Shared secret for verify and replay signing. |
| `signature_header` | `X-Signature` | Header carrying the `algo=hexdigest` signature. |
| `algorithm` | `sha256` | HMAC algorithm (`sha1`, `sha256`, or `sha512`). |
| `capture_limit` | `100` | Deliveries retained before the oldest is dropped. |

## Testing

```bash
pip install -e ".[dev]"
pytest
```

The suite covers signing and verification (including tamper, wrong-secret, and
malformed-input cases) and every endpoint through the Flask test client, using
an injected fake poster so replay is exercised without any network call.

## License

MIT. See [LICENSE](LICENSE).

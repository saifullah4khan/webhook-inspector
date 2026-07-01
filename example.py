"""Runnable demo of the webhook inspector.

Starts the inspector on port 8000 with a demo signing secret and prints a
ready-to-paste curl command whose body is correctly signed, so you can watch a
valid delivery get captured end to end.

    python example.py
"""

from __future__ import annotations

from webhook_inspector import create_app, sign

DEMO_SECRET = "demo-secret"
SAMPLE_BODY = b'{"event":"order.paid","order_id":1001}'


def main() -> None:
    signature = sign(SAMPLE_BODY, DEMO_SECRET)
    print("Inspector starting on http://localhost:8000")
    print("\nIn another terminal, send a correctly signed delivery:\n")
    print(
        "  curl -X POST http://localhost:8000/webhook \\\n"
        f"    -H 'X-Signature: {signature}' \\\n"
        "    -H 'Content-Type: application/json' \\\n"
        f"    -d '{SAMPLE_BODY.decode()}'\n"
    )
    print("Then inspect what arrived:\n")
    print("  curl http://localhost:8000/captures\n")

    app = create_app(secret=DEMO_SECRET)
    app.run(port=8000)


if __name__ == "__main__":
    main()

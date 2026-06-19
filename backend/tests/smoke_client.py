"""Manual two-client smoke test for the relay.

Starts two WebSocket clients, joins them to the same room, sends an opaque
(base64) payload from one, and verifies the other receives it verbatim. The
"ciphertext" here is just base64 of plaintext — the server can't tell the
difference, which is exactly the point.

Run the server first:   python backend/main.py
Then:                   python backend/tests/smoke_client.py
"""
import asyncio
import base64
import json
import secrets

import websockets

URL = "ws://127.0.0.1:8000/ws"
ROOM = secrets.token_hex(32)  # 64 hex chars = 256-bit room id


async def main() -> None:
    async with websockets.connect(URL) as a, websockets.connect(URL) as b:
        await a.send(json.dumps({"type": "join", "room": ROOM}))
        await b.send(json.dumps({"type": "join", "room": ROOM}))
        print("A join ->", await a.recv())
        print("B join ->", await b.recv())

        payload = base64.b64encode(b"hello over the relay").decode("ascii")
        await a.send(json.dumps({"type": "msg", "room": ROOM, "payload": payload, "alg": "AES256"}))

        received = json.loads(await b.recv())
        print("B received ->", received)
        assert received["payload"] == payload, "payload mismatch!"
        decoded = base64.b64decode(received["payload"]).decode("ascii")
        print("B decoded  ->", decoded)
        assert decoded == "hello over the relay"
        print("\nOK: relay forwarded opaque payload verbatim.")


if __name__ == "__main__":
    asyncio.run(main())

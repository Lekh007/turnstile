"""A minimal, real MCP server over stdio, used to test the proxy for real.

Not a mock. It is a separate process that speaks the actual wire protocol, so
the tests that drive it exercise subprocess spawning, newline framing, stdout
purity and shutdown-on-EOF -- none of which a fake object can prove.

It deliberately misbehaves in two controllable ways, because the interesting
proxy behaviour is on the unhappy paths:

* `TURNSTILE_FAKE_NOISY=1` writes a line to *stderr* before answering, which a
  correct client must ignore rather than treat as failure.
* `TURNSTILE_FAKE_NOTIFY=1` emits a notification before each response, so the
  reader has to sort interleaved notifications from real answers.

Usage: `python fake_mcp_server.py <server-label>`
"""

from __future__ import annotations

import json
import os
import sys


def emit(message: dict[str, object]) -> None:
    # One message per line, no embedded newlines: the newline is the frame.
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main() -> int:
    label = sys.argv[1] if len(sys.argv) > 1 else "fake"
    noisy = os.environ.get("TURNSTILE_FAKE_NOISY") == "1"
    notify = os.environ.get("TURNSTILE_FAKE_NOTIFY") == "1"

    if noisy:
        print(f"{label}: starting up", file=sys.stderr, flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue

        identifier = message.get("id")
        method = message.get("method")

        if identifier is None:
            # A notification. Never answer one.
            if noisy:
                print(f"{label}: notification {method}", file=sys.stderr, flush=True)
            continue

        if notify:
            emit({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}})

        if method == "tools/list":
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "result": {
                        "resultType": "complete",
                        "tools": [
                            {
                                "name": "read_file",
                                "description": f"Read a file via {label}",
                                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                            },
                            {
                                "name": "delete_file",
                                "description": f"Delete a file via {label}",
                                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                            },
                        ],
                    },
                }
            )
        elif method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "result": {
                        "resultType": "complete",
                        "content": [{"type": "text", "text": f"{label}:{name}:{json.dumps(arguments, sort_keys=True)}"}],
                        "isError": False,
                    },
                }
            )
        else:
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": identifier,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
            )

    # stdin reached EOF: exit promptly, as the transport requires.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

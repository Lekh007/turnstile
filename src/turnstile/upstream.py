"""Talking to one real MCP server over stdio.

The framing is the whole job: one JSON-RPC message per line, newline
delimited, no embedded newlines. Everything else here exists to handle the two
things that make that harder than it sounds.

**Responses are not the only thing that comes back.** A server may interleave
notifications (progress, logging) with responses on the same stream, so a
reader that assumes "the next line is my answer" will eventually hand a
progress notification to the caller as a result. A background thread therefore
drains stdout continuously, sorting responses by JSON-RPC id and setting
notifications aside for the proxy to forward.

**A hung server must not hang the gateway.** Requests wait on a queue with a
deadline rather than blocking on `readline()` forever, so an upstream that
stops answering fails one call instead of wedging the process.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from collections import deque
from typing import Any, Protocol

DEFAULT_TIMEOUT_SECONDS = 30.0


class UpstreamError(RuntimeError):
    """The upstream could not be reached or did not answer in time."""


class Upstream(Protocol):
    """What the proxy needs from a downstream MCP server.

    A Protocol so the routing and policy layers can be tested without spawning
    a single subprocess, and so a future Streamable HTTP transport drops in
    without either layer knowing it changed.
    """

    name: str

    def request(self, message: dict[str, Any], *, timeout: float = ...) -> dict[str, Any]: ...

    def notify(self, message: dict[str, Any]) -> None: ...

    def drain_notifications(self) -> list[dict[str, Any]]: ...

    def stop(self) -> None: ...


def log(message: str) -> None:
    """Write a diagnostic line to stderr.

    Never stdout. The specification is explicit that a server "MUST NOT write
    anything to its stdout that is not a valid MCP message", and a proxy has
    two stdouts to respect -- its own and every upstream's. One stray `print`
    corrupts the stream for the client, which then sees a JSON parse failure
    rather than anything resembling the actual bug. stderr is explicitly
    allowed for exactly this, and clients are told not to read it as failure.
    """
    print(message, file=sys.stderr, flush=True)


class StdioUpstream:
    """An MCP server running as a child process, spoken to over its stdio."""

    def __init__(
        self,
        name: str,
        command: str,
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        if "." in name:
            # Routing splits a prefixed tool name on its first dot, so a dot in
            # a server name would make `a.b.read` ambiguous. Rejected here
            # rather than producing a confusing route later.
            raise ValueError(f"server name must not contain '.': {name!r}")
        self.name = name
        self._command = [command, *(args or [])]
        self._env = env
        self._process: subprocess.Popen[str] | None = None
        self._responses: dict[str | int, queue.Queue[dict[str, Any]]] = {}
        self._notifications: deque[dict[str, Any]] = deque()
        self._lock = threading.Lock()
        self._reader: threading.Thread | None = None

    def start(self) -> None:
        self._process = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_loop, name=f"turnstile-{self.name}", daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                # A server that writes non-JSON to stdout is violating the
                # transport. Report it and keep going rather than killing the
                # gateway over one bad line from one upstream.
                log(f"[turnstile] upstream {self.name!r} wrote a non-JSON line to stdout; ignoring")
                continue
            if not isinstance(message, dict):
                continue
            identifier = message.get("id")
            if identifier is None:
                with self._lock:
                    self._notifications.append(message)
                continue
            with self._lock:
                waiter = self._responses.get(identifier)
            if waiter is not None:
                waiter.put(message)
            else:
                log(f"[turnstile] upstream {self.name!r} answered unknown id {identifier!r}; dropping")

    def request(self, message: dict[str, Any], *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
        identifier = message.get("id")
        if identifier is None:
            raise UpstreamError("request() requires a JSON-RPC id; use notify() for notifications")

        waiter: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        with self._lock:
            self._responses[identifier] = waiter
        try:
            self._write(message)
            try:
                return waiter.get(timeout=timeout)
            except queue.Empty as exc:
                raise UpstreamError(f"upstream {self.name!r} did not respond within {timeout}s") from exc
        finally:
            with self._lock:
                self._responses.pop(identifier, None)

    def notify(self, message: dict[str, Any]) -> None:
        self._write(message)

    def drain_notifications(self) -> list[dict[str, Any]]:
        """Take everything the upstream has emitted that wasn't a response."""
        with self._lock:
            drained = list(self._notifications)
            self._notifications.clear()
        return drained

    def _write(self, message: dict[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise UpstreamError(f"upstream {self.name!r} is not running")
        # separators without spaces and no indent: the encoded message must not
        # contain a newline, since the newline *is* the frame delimiter.
        line = json.dumps(message, separators=(",", ":"))
        try:
            process.stdin.write(line + "\n")
            process.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise UpstreamError(f"upstream {self.name!r} closed its input stream") from exc

    def stop(self, *, timeout: float = 5.0) -> None:
        """Shut down as the specification prescribes: close stdin, wait, then force.

        Servers are told to exit when stdin reaches EOF, and that is the only
        portable graceful signal, so it is tried first. Escalation exists
        because "SHOULD exit promptly" is not "will".
        """
        process = self._process
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
        except (BrokenPipeError, ValueError):
            pass
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            log(f"[turnstile] upstream {self.name!r} did not exit on stdin close; terminating")
            process.terminate()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                log(f"[turnstile] upstream {self.name!r} ignored terminate; killing")
                process.kill()
        finally:
            self._process = None

    def __enter__(self) -> StdioUpstream:
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

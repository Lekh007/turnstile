"""The stdio server Turnstile presents to an MCP client.

The client spawns this process and speaks to it exactly as it would speak to
any MCP server; Turnstile in turn speaks to the real servers. From the client's
side there is one server with every tool on it, and from each real server's
side there is one well-behaved client.

The invariant that matters most is dull and absolute: **stdout carries MCP
messages and nothing else.** The specification puts it as a MUST NOT, and the
failure mode when it is broken is disproportionate -- a stray banner, warning
or traceback on stdout makes the client fail to parse the stream, and the error
it reports points at JSON rather than at whatever actually printed. Every
diagnostic in this codebase goes to stderr through `upstream.log`, which the
specification explicitly permits and tells clients not to read as failure.

What this slice handles: `server/discover`, `tools/list`, `tools/call`, and
notification passthrough. Anything else is answered with `-32601`, which is
honest -- a proxy that silently forwarded methods it does not understand to an
arbitrary upstream would be guessing about routing, and guessing is how a call
meant for staging reaches production.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from typing import Any, TextIO

from .approvals import ApprovalStore
from .audit import AuditLog
from .budget import Budget, BudgetLedger
from .domain import Principal
from .gateway import Gateway
from .mcp import (
    JSONRPC_VERSION,
    PROTOCOL_VERSION_KEY,
    MalformedRequest,
    error_response,
    filter_tool_list,
    require_meta,
)
from .policy import Policy
from .registry import ToolRegistry
from .upstream import Upstream, UpstreamError, log

SUPPORTED_PROTOCOL_VERSIONS = ("2026-07-28",)
SERVER_INFO = {"name": "turnstile", "version": "0.1.0"}

METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603
UNSUPPORTED_PROTOCOL_VERSION = -32022
"""Defined by the specification (schema: UnsupportedProtocolVersionError), not invented here."""


class UpstreamTransportAdapter:
    """Lets `Gateway` forward a call without knowing about routing or prefixes.

    The gateway's contract is `call(server, message)`. Registry lookup and the
    prefix rewrite happen here so the governance layer stays free of transport
    concerns -- it should be reviewable without anyone needing to understand
    stdio framing.
    """

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def call(self, server: str, message: dict[str, Any]) -> dict[str, Any]:
        upstream = self._registry.upstream(server)
        if upstream is None:
            raise UpstreamError(f"no upstream named {server!r}")
        return upstream.request(message)


class Proxy:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy: Policy,
        audit_log: AuditLog,
        principal: Principal,
        budget: Budget | None = None,
        ledger: BudgetLedger | None = None,
        approvals: ApprovalStore | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._principal = principal
        self._gateway = Gateway(
            policy=policy,
            transport=UpstreamTransportAdapter(registry),
            audit_log=audit_log,
            budget=budget,
            ledger=ledger,
            approvals=approvals,
        )

    # -- the loop ---------------------------------------------------------

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        """Read newline-delimited messages until EOF, then return.

        Returning on EOF is the specified graceful shutdown: a server "SHOULD
        exit promptly when their standard input is closed", because that is the
        only portable signal a client has.
        """
        source = stdin if stdin is not None else sys.stdin
        sink = stdout if stdout is not None else sys.stdout
        for line in source:
            line = line.strip()
            if not line:
                continue
            for message in self.handle_line(line):
                self._emit(message, sink)

    def _emit(self, message: dict[str, Any], sink: TextIO) -> None:
        # No indent, compact separators: the encoded form must not contain a
        # newline, because the newline is the frame boundary.
        sink.write(json.dumps(message, separators=(",", ":")) + "\n")
        sink.flush()

    def handle_line(self, line: str) -> list[dict[str, Any]]:
        """Turn one input line into zero or more messages to write back.

        Returns a list rather than writing directly so the whole routing and
        policy path is testable without any streams at all.
        """
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            log("[turnstile] client sent a line that is not JSON; ignoring")
            return [error_response(None, code=-32700, message="Parse error")]
        if not isinstance(message, dict):
            return [error_response(None, code=-32600, message="Invalid Request")]
        return self.handle_message(message)

    def handle_message(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        method = message.get("method")
        identifier = message.get("id")

        # A notification has no id and must never be answered. Forwarding
        # rather than dropping matters for notifications/cancelled: an upstream
        # that never hears about a cancellation keeps working on it.
        if identifier is None:
            if isinstance(method, str):
                self._broadcast_notification(message)
            return []

        if method == "server/discover":
            return [self._discover(message, identifier)]
        if method == "tools/list":
            return [self._tools_list(message, identifier)]
        if method == "tools/call":
            return [self._tools_call(message, identifier)]

        return [
            error_response(
                identifier,
                code=METHOD_NOT_FOUND,
                message=(
                    f"Turnstile does not proxy {method!r}. This gateway governs tools/call and "
                    "tools/list; forwarding an unrecognised method would mean guessing which "
                    "upstream it was meant for."
                ),
            )
        ]

    # -- methods ----------------------------------------------------------

    def _discover(self, message: dict[str, Any], identifier: str | int) -> dict[str, Any]:
        """Answer the modern probe that replaced the `initialize` handshake.

        Servers MUST implement this, and a client uses it to tell a modern
        server from a legacy one. Turnstile answers as itself rather than
        forwarding: it is the server the client is talking to, and its own
        supported versions are what govern the conversation.
        """
        return {
            "jsonrpc": JSONRPC_VERSION,
            "id": identifier,
            "result": {
                "resultType": "complete",
                "supportedVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                "_meta": {"io.modelcontextprotocol/serverInfo": SERVER_INFO},
            },
        }

    def _tools_list(self, message: dict[str, Any], identifier: str | int) -> dict[str, Any]:
        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        version_error = self._check_version(params, identifier)
        if version_error is not None:
            return version_error

        results: dict[str, dict[str, Any]] = {}
        for name in self._registry.server_names:
            upstream = self._registry.upstream(name)
            if upstream is None:
                continue
            try:
                response = upstream.request({**message, "id": f"turnstile-list-{name}"})
            except UpstreamError as exc:
                # One unreachable server must not blank the whole tool list --
                # the other servers' tools are still perfectly usable.
                log(f"[turnstile] tools/list failed for upstream {name!r}: {exc}")
                continue
            result = response.get("result")
            if isinstance(result, dict):
                results[name] = result

        aggregated = self._registry.aggregate_tools(results)
        allowed = {
            tool["name"]
            for tool in aggregated
            if self._is_listable(tool["name"])
        }
        filtered = filter_tool_list({"resultType": "complete", "tools": aggregated}, allowed)
        return {"jsonrpc": JSONRPC_VERSION, "id": identifier, "result": filtered}

    def _is_listable(self, qualified: str) -> bool:
        """Would policy allow this tool at all, ignoring its arguments?

        Argument predicates cannot be evaluated without a call, so a tool that
        is only conditionally denied still appears in the list and is judged
        properly at call time. Hiding it would be worse: the model would not
        know the capability exists even for the arguments that are permitted.
        """
        route = self._registry.resolve(qualified)
        if route is None:
            return False
        from .domain import ToolCall

        probe = ToolCall(
            server=route.server,
            tool=route.tool,
            arguments={},
            principal=self._principal,
        )
        return self._policy.evaluate(probe).effect.value != "deny"

    def _tools_call(self, message: dict[str, Any], identifier: str | int) -> dict[str, Any]:
        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        version_error = self._check_version(params, identifier)
        if version_error is not None:
            return version_error

        qualified = params.get("name")
        if not isinstance(qualified, str) or not qualified:
            return error_response(identifier, code=-32602, message="params.name must be a non-empty string")

        route = self._registry.resolve(qualified)
        if route is None:
            return error_response(
                identifier,
                code=METHOD_NOT_FOUND,
                message=(
                    f"Unknown tool: {qualified!r}. Tools are exposed as '<server>.<tool>'; "
                    f"known servers are {', '.join(self._registry.server_names) or 'none'}."
                ),
            )

        # The upstream knows its tool by the unprefixed name, so the prefix is
        # stripped before forwarding. Policy is evaluated against the same
        # unprefixed name, so a rule reads `tools=("read_file",)` rather than
        # repeating the server in two places.
        forwarded = {**message, "params": {**params, "name": route.tool}}
        result = self._gateway.handle(route.server, forwarded, self._principal)
        return result.response

    def _check_version(self, params: dict[str, Any], identifier: str | int) -> dict[str, Any] | None:
        """Reject a protocol version this gateway does not speak.

        Returns the specification's UnsupportedProtocolVersionError shape, whose
        `data.supported` list is what lets a client retry with a version that
        works instead of simply failing.
        """
        try:
            meta = require_meta(params)
        except MalformedRequest as exc:
            return error_response(identifier, code=exc.code, message=exc.message)

        requested = meta[PROTOCOL_VERSION_KEY]
        if requested not in SUPPORTED_PROTOCOL_VERSIONS:
            return {
                "jsonrpc": JSONRPC_VERSION,
                "id": identifier,
                "error": {
                    "code": UNSUPPORTED_PROTOCOL_VERSION,
                    "message": "Unsupported protocol version",
                    "data": {"supported": list(SUPPORTED_PROTOCOL_VERSIONS), "requested": requested},
                },
            }
        return None

    def _broadcast_notification(self, message: dict[str, Any]) -> None:
        """Send a client notification to every upstream.

        Broadcast rather than routed because a notification carries no tool
        name to route by. For `notifications/cancelled` this is the safe
        direction to be wrong in: a server that never started the work ignores
        it, whereas a server that never hears it keeps going.
        """
        for name in self._registry.server_names:
            upstream = self._registry.upstream(name)
            if upstream is None:
                continue
            try:
                upstream.notify(message)
            except UpstreamError as exc:
                log(f"[turnstile] could not forward notification to {name!r}: {exc}")

    def collect_upstream_notifications(self) -> Iterable[dict[str, Any]]:
        """Anything the upstreams emitted that was not a response to a request."""
        for name in self._registry.server_names:
            upstream: Upstream | None = self._registry.upstream(name)
            if upstream is None:
                continue
            yield from upstream.drain_notifications()

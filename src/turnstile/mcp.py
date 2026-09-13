"""MCP wire types, per the 2026-07-28 specification revision.

Only the parts a governance gateway must understand are modelled: `tools/call`,
`tools/list`, and the shapes of results and errors. Everything else is forwarded
untouched, because a proxy that only understands half a protocol should not be
rewriting the other half.

Three requirements from that revision drive this module:

* **Results carry `resultType`.** `"complete"` or `"input_required"`. A result
  with no `resultType` comes from a server speaking an earlier revision and
  MUST be read as `"complete"`.
* **Requests carry required `_meta`.** Every client request must supply
  `io.modelcontextprotocol/protocolVersion` and
  `io.modelcontextprotocol/clientCapabilities`; a request missing either is
  malformed and gets `-32602`. This is what statelessness costs -- the gateway
  may not remember a handshake, so it checks every message.
* **Error-code ranges are allocated.** `-32020` to `-32099` belong to the
  specification. Turnstile therefore refuses calls with a *result* carrying
  `isError: true` rather than inventing a JSON-RPC code, which is also the
  better behaviour: the spec says clients SHOULD hand tool execution errors to
  the model so it can self-correct, and "you may not call this" is precisely
  the kind of thing a model should adapt to rather than retry.
"""

from __future__ import annotations

from typing import Any, Final

JSONRPC_VERSION: Final = "2.0"
PROTOCOL_VERSION_KEY: Final = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_KEY: Final = "io.modelcontextprotocol/clientCapabilities"

INVALID_PARAMS: Final = -32602
"""JSON-RPC 'Invalid params'. Used for malformed `_meta`, as the spec requires."""

RESULT_COMPLETE: Final = "complete"


class MalformedRequest(Exception):
    """A request that cannot be evaluated. Carries the JSON-RPC code to return."""

    def __init__(self, message: str, *, code: int = INVALID_PARAMS) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def parse_tool_call(message: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Extract `(name, arguments)` from a `tools/call` request.

    Validates the `_meta` fields the specification marks required. This is not
    pedantry: those fields exist precisely so a stateless intermediary like this
    one can identify the protocol version and capabilities of a request without
    having seen the connection's history, and a proxy that skips the check will
    happily forward messages an upstream server must reject.
    """
    if message.get("jsonrpc") != JSONRPC_VERSION:
        raise MalformedRequest(f"jsonrpc must be {JSONRPC_VERSION!r}")
    if message.get("method") != "tools/call":
        raise MalformedRequest(f"expected method 'tools/call', got {message.get('method')!r}")

    params = message.get("params")
    if not isinstance(params, dict):
        raise MalformedRequest("params must be an object")

    require_meta(params)

    name = params.get("name")
    if not isinstance(name, str) or not name:
        raise MalformedRequest("params.name must be a non-empty string")

    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise MalformedRequest("params.arguments must be an object when present")

    return name, arguments


def require_meta(params: dict[str, Any]) -> dict[str, Any]:
    """Validate the per-request `_meta` fields the 2026-07-28 revision requires."""
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        raise MalformedRequest("params._meta is required and must be an object")
    missing = [key for key in (PROTOCOL_VERSION_KEY, CLIENT_CAPABILITIES_KEY) if key not in meta]
    if missing:
        raise MalformedRequest(f"params._meta is missing required fields: {', '.join(missing)}")
    if not isinstance(meta[PROTOCOL_VERSION_KEY], str):
        raise MalformedRequest(f"{PROTOCOL_VERSION_KEY} must be a string")
    if not isinstance(meta[CLIENT_CAPABILITIES_KEY], dict):
        raise MalformedRequest(f"{CLIENT_CAPABILITIES_KEY} must be an object")
    return meta


def is_complete(result: dict[str, Any]) -> bool:
    """Whether a result is final.

    An absent `resultType` means a server on an earlier revision, which the
    specification says to treat as `"complete"`. Defaulting the other way would
    make every pre-2026-07-28 server look like it was asking for more input.
    """
    return bool(result.get("resultType", RESULT_COMPLETE) == RESULT_COMPLETE)


def text_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    """A minimal well-formed `tools/call` result."""
    return {
        "resultType": RESULT_COMPLETE,
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


def denial_response(request_id: str | int | None, *, reason: str, rule_id: str) -> dict[str, Any]:
    """The message a caller receives when policy refuses the call.

    Deliberately a *result* with `isError: true`, not a JSON-RPC error. Three
    reasons: the specification reserves the nearby error-code range for itself;
    clients SHOULD pass tool execution errors to the model, which is what makes
    a refusal something the agent can route around; and a refusal is not a
    transport failure, so it must not be indistinguishable from one.

    The rule id is included on purpose. A caller who cannot see *why* they were
    refused will retry, and an agent that retries a denial in a loop is a worse
    outcome than telling it plainly that the door is closed.
    """
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "result": text_result(
            f"Refused by Turnstile policy [{rule_id}]: {reason}",
            is_error=True,
        ),
    }


def error_response(request_id: str | int | None, *, code: int, message: str) -> dict[str, Any]:
    """A JSON-RPC error response, for malformed requests only."""
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def filter_tool_list(result: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    """Drop tools the caller may not invoke from a `tools/list` result.

    The specification explicitly permits this: the tool set "MAY vary by the
    authorization presented on the request -- for example, returning only the
    tools the caller's granted scopes permit". Filtering here means a model is
    never shown a tool it would only be refused for using, which removes a whole
    class of wasted turns.

    Note what this is not: a security boundary on its own. A caller can still
    name an unlisted tool directly, so `tools/call` is always evaluated against
    policy regardless of what this returned.
    """
    tools = result.get("tools")
    if not isinstance(tools, list):
        return result
    kept = [tool for tool in tools if isinstance(tool, dict) and tool.get("name") in allowed]
    return {**result, "tools": kept}

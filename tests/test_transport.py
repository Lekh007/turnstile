"""Transport and proxy tests.

The `TestRealSubprocess` class spawns the fixture server for real. Everything
it covers -- framing, interleaved notifications, stderr tolerance, shutdown on
EOF -- is invisible to a mocked transport, and those are exactly the things
that break when a proxy meets a real MCP server for the first time.
"""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from turnstile.audit import AuditLog
from turnstile.domain import Effect, Principal
from turnstile.policy import ArgumentPredicate, Policy, Rule
from turnstile.proxy import SUPPORTED_PROTOCOL_VERSIONS, Proxy
from turnstile.registry import ToolRegistry
from turnstile.upstream import StdioUpstream, UpstreamError

FIXTURE = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"
PRINCIPAL = Principal(tenant="acme", subject="agent-1", scopes=("read",))
VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]


def meta() -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def call_message(name: str, arguments: dict[str, Any] | None = None, *, identifier: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": identifier,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}, "_meta": meta()},
    }


def list_message(identifier: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "method": "tools/list", "params": {"_meta": meta()}}


def spawn(label: str, **env: str) -> StdioUpstream:
    upstream = StdioUpstream(
        label,
        sys.executable,
        [str(FIXTURE), label],
        env={**os.environ, **env},
    )
    upstream.start()
    return upstream


class FakeUpstream:
    """In-process stand-in for the routing tests that do not need a subprocess."""

    def __init__(self, name: str, tools: list[str] | None = None, *, fail: bool = False) -> None:
        self.name = name
        self.received: list[dict[str, Any]] = []
        self.notifications_sent: list[dict[str, Any]] = []
        self._tools = tools if tools is not None else ["read_file", "delete_file"]
        self._fail = fail

    def request(self, message: dict[str, Any], *, timeout: float = 30.0) -> dict[str, Any]:
        if self._fail:
            raise UpstreamError(f"{self.name} is down")
        self.received.append(message)
        identifier = message.get("id")
        if message.get("method") == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": identifier,
                "result": {"resultType": "complete", "tools": [{"name": t} for t in self._tools]},
            }
        params = message.get("params") or {}
        return {
            "jsonrpc": "2.0",
            "id": identifier,
            "result": {
                "resultType": "complete",
                "content": [{"type": "text", "text": f"{self.name}:{params.get('name')}"}],
                "isError": False,
            },
        }

    def notify(self, message: dict[str, Any]) -> None:
        if self._fail:
            raise UpstreamError(f"{self.name} is down")
        self.notifications_sent.append(message)

    def drain_notifications(self) -> list[dict[str, Any]]:
        return []

    def stop(self) -> None:
        return None


def build_proxy(
    upstreams: dict[str, Any], policy: Policy | None = None
) -> tuple[Proxy, AuditLog]:
    log = AuditLog()
    proxy = Proxy(
        registry=ToolRegistry(upstreams),
        policy=policy if policy is not None else Policy(rules=(Rule(id="allow-all", effect=Effect.ALLOW),)),
        audit_log=log,
        principal=PRINCIPAL,
    )
    return proxy, log


class TestRealSubprocess:
    def test_round_trips_a_tool_call_through_a_real_process(self) -> None:
        with StdioUpstream("files", sys.executable, [str(FIXTURE), "files"]) as upstream:
            response = upstream.request(call_message("read_file", {"path": "/tmp/x"}))
        assert response["id"] == 1
        assert response["result"]["content"][0]["text"].startswith("files:read_file:")

    def test_stderr_output_is_not_treated_as_failure(self) -> None:
        # The spec says clients "SHOULD NOT assume stderr output indicates
        # error conditions". A server that logs must still work.
        upstream = spawn("noisy", TURNSTILE_FAKE_NOISY="1")
        try:
            response = upstream.request(call_message("read_file"))
            assert "result" in response
        finally:
            upstream.stop()

    def test_notifications_interleaved_with_responses_are_sorted_correctly(self) -> None:
        # The failure this prevents: returning a progress notification to the
        # caller as though it were the tool's result.
        upstream = spawn("chatty", TURNSTILE_FAKE_NOTIFY="1")
        try:
            response = upstream.request(call_message("read_file"))
            assert response["id"] == 1
            assert "result" in response
            assert "method" not in response
            notifications = upstream.drain_notifications()
            assert any(n.get("method") == "notifications/message" for n in notifications)
        finally:
            upstream.stop()

    def test_responses_match_their_own_ids_across_several_calls(self) -> None:
        with StdioUpstream("files", sys.executable, [str(FIXTURE), "files"]) as upstream:
            for identifier in (7, 8, 9):
                response = upstream.request(call_message("read_file", identifier=identifier))
                assert response["id"] == identifier

    def test_server_exits_when_stdin_closes(self) -> None:
        upstream = StdioUpstream("files", sys.executable, [str(FIXTURE), "files"])
        upstream.start()
        upstream.request(call_message("read_file"))
        upstream.stop(timeout=10.0)  # closes stdin first; must not need a kill
        assert upstream._process is None

    def test_request_on_a_stopped_upstream_is_an_error_not_a_hang(self) -> None:
        upstream = StdioUpstream("files", sys.executable, [str(FIXTURE), "files"])
        upstream.start()
        upstream.stop()
        with pytest.raises(UpstreamError, match="not running"):
            upstream.request(call_message("read_file"))

    def test_server_name_with_a_dot_is_rejected(self) -> None:
        # Routing splits on the first dot, so a dotted server name would make
        # the route ambiguous.
        with pytest.raises(ValueError, match="must not contain"):
            StdioUpstream("a.b", sys.executable, [str(FIXTURE)])

    def test_end_to_end_through_the_proxy_with_two_real_servers(self) -> None:
        files = spawn("files")
        db = spawn("db")
        try:
            policy = Policy(
                rules=(
                    Rule(id="no-deletes", effect=Effect.DENY, description="Deletion is not delegated.",
                         tools=("delete_file",)),
                    Rule(id="allow-rest", effect=Effect.ALLOW),
                )
            )
            proxy, log = build_proxy({"files": files, "db": db}, policy)

            listed = proxy.handle_message(list_message())[0]
            names = [tool["name"] for tool in listed["result"]["tools"]]
            assert "files.read_file" in names
            assert "db.read_file" in names
            assert "files.delete_file" not in names, "a denied tool should not be advertised"

            allowed = proxy.handle_message(call_message("files.read_file", {"path": "/x"}))[0]
            assert allowed["result"]["isError"] is False
            assert "files:read_file" in allowed["result"]["content"][0]["text"]

            denied = proxy.handle_message(call_message("db.delete_file", {"path": "/x"}))[0]
            assert denied["result"]["isError"] is True
            assert "no-deletes" in denied["result"]["content"][0]["text"]

            assert log.verify() == 2
            log.close()
        finally:
            files.stop()
            db.stop()


class TestRouting:
    def test_tools_are_prefixed_by_server(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files"), "db": FakeUpstream("db")})
        result = proxy.handle_message(list_message())[0]["result"]
        assert [tool["name"] for tool in result["tools"]] == [
            "db.read_file",
            "db.delete_file",
            "files.read_file",
            "files.delete_file",
        ]
        log.close()

    def test_identical_tool_names_on_two_servers_stay_distinct(self) -> None:
        # The collision the spec warns aggregating proxies about.
        files = FakeUpstream("files", ["search"])
        db = FakeUpstream("db", ["search"])
        proxy, log = build_proxy({"files": files, "db": db})
        proxy.handle_message(call_message("db.search", {"q": "x"}))
        assert files.received == []
        assert len(db.received) == 1
        log.close()

    def test_prefix_is_stripped_before_forwarding(self) -> None:
        files = FakeUpstream("files")
        proxy, log = build_proxy({"files": files})
        proxy.handle_message(call_message("files.read_file"))
        assert files.received[0]["params"]["name"] == "read_file"
        log.close()

    def test_split_is_on_the_first_dot_so_dotted_tool_names_survive(self) -> None:
        # 'admin.tools.list' is itself a legal tool name per the spec.
        files = FakeUpstream("files", ["admin.tools.list"])
        proxy, log = build_proxy({"files": files})
        proxy.handle_message(call_message("files.admin.tools.list"))
        assert files.received[0]["params"]["name"] == "admin.tools.list"
        log.close()

    def test_unknown_server_is_method_not_found_not_a_guess(self) -> None:
        files = FakeUpstream("files")
        proxy, log = build_proxy({"files": files})
        response = proxy.handle_message(call_message("nope.read_file"))[0]
        assert response["error"]["code"] == -32601
        assert files.received == [], "an unroutable call must not be sent anywhere"
        log.close()

    def test_unprefixed_tool_name_is_rejected(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files")})
        assert proxy.handle_message(call_message("read_file"))[0]["error"]["code"] == -32601
        log.close()

    def test_one_dead_server_does_not_blank_the_whole_tool_list(self) -> None:
        proxy, log = build_proxy({"up": FakeUpstream("up"), "down": FakeUpstream("down", fail=True)})
        names = [t["name"] for t in proxy.handle_message(list_message())[0]["result"]["tools"]]
        assert names == ["up.read_file", "up.delete_file"]
        log.close()


class TestProtocolConformance:
    def test_discover_reports_supported_versions(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files")})
        result = proxy.handle_message({"jsonrpc": "2.0", "id": 1, "method": "server/discover"})[0]["result"]
        assert result["supportedVersions"] == list(SUPPORTED_PROTOCOL_VERSIONS)
        assert result["resultType"] == "complete"
        log.close()

    def test_unsupported_version_returns_the_specified_error_shape(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files")})
        message = call_message("files.read_file")
        message["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = "1900-01-01"
        error = proxy.handle_message(message)[0]["error"]
        assert error["code"] == -32022
        assert error["data"]["requested"] == "1900-01-01"
        assert error["data"]["supported"] == list(SUPPORTED_PROTOCOL_VERSIONS)
        log.close()

    def test_missing_required_meta_is_invalid_params(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files")})
        message = call_message("files.read_file")
        del message["params"]["_meta"]
        assert proxy.handle_message(message)[0]["error"]["code"] == -32602
        log.close()

    def test_notifications_are_never_answered(self) -> None:
        files = FakeUpstream("files")
        proxy, log = build_proxy({"files": files})
        responses = proxy.handle_message({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                         "params": {"requestId": 1}})
        assert responses == [], "a notification must not produce a response"
        assert files.notifications_sent[0]["method"] == "notifications/cancelled"
        log.close()

    def test_cancellation_reaches_every_upstream(self) -> None:
        # A server that never hears a cancellation keeps burning work on it.
        a, b = FakeUpstream("a"), FakeUpstream("b")
        proxy, log = build_proxy({"a": a, "b": b})
        proxy.handle_message({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}})
        assert len(a.notifications_sent) == 1
        assert len(b.notifications_sent) == 1
        log.close()

    def test_unproxied_method_is_refused_rather_than_guessed_at(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files")})
        response = proxy.handle_message({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {}})[0]
        assert response["error"]["code"] == -32601
        assert "guessing" in response["error"]["message"]
        log.close()


class TestStdoutPurity:
    """stdout carries MCP messages and nothing else.

    A stray banner or traceback on stdout makes the client fail to parse the
    stream, and the error it surfaces points at JSON rather than at whatever
    printed. This is the single most common way a working proxy breaks.
    """

    def test_every_stdout_line_is_a_valid_mcp_message(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files")})
        stdin = io.StringIO(
            "\n".join(
                [
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}),
                    json.dumps(list_message(2)),
                    json.dumps(call_message("files.read_file", identifier=3)),
                    json.dumps(call_message("nope.read_file", identifier=4)),
                    json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled"}),
                    "   ",
                    "this line is not json at all",
                ]
            )
        )
        stdout = io.StringIO()
        proxy.serve(stdin=stdin, stdout=stdout)

        lines = [line for line in stdout.getvalue().splitlines() if line]
        assert lines, "the proxy produced no output at all"
        for line in lines:
            parsed = json.loads(line)  # raises if anything non-JSON reached stdout
            assert parsed["jsonrpc"] == "2.0"
            assert "result" in parsed or "error" in parsed
            assert "\n" not in line
        log.close()

    def test_serve_returns_on_eof_rather_than_hanging(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files")})
        proxy.serve(stdin=io.StringIO(""), stdout=io.StringIO())
        log.close()

    def test_a_notification_produces_no_stdout_line(self) -> None:
        proxy, log = build_proxy({"files": FakeUpstream("files")})
        stdout = io.StringIO()
        proxy.serve(
            stdin=io.StringIO(json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled"})),
            stdout=stdout,
        )
        assert stdout.getvalue() == ""
        log.close()


class TestPolicyThroughTheProxy:
    def test_denied_call_never_reaches_the_upstream(self) -> None:
        files = FakeUpstream("files")
        policy = Policy(rules=(Rule(id="no-delete", effect=Effect.DENY, tools=("delete_file",)),))
        proxy, log = build_proxy({"files": files}, policy)
        response = proxy.handle_message(call_message("files.delete_file"))[0]
        assert response["result"]["isError"] is True
        assert files.received == []
        log.close()

    def test_conditionally_denied_tool_is_still_listed(self) -> None:
        # Argument predicates cannot be judged without arguments, so hiding the
        # tool would deny the model a capability that is legal for some inputs.
        policy = Policy(
            rules=(
                Rule(
                    id="no-etc",
                    effect=Effect.DENY,
                    tools=("read_file",),
                    arguments=(ArgumentPredicate(path="path", operator="glob", value="/etc/*"),),
                ),
                Rule(id="allow", effect=Effect.ALLOW),
            )
        )
        proxy, log = build_proxy({"files": FakeUpstream("files")}, policy)
        names = [t["name"] for t in proxy.handle_message(list_message())[0]["result"]["tools"]]
        assert "files.read_file" in names

        blocked = proxy.handle_message(call_message("files.read_file", {"path": "/etc/passwd"}))[0]
        assert blocked["result"]["isError"] is True
        allowed = proxy.handle_message(call_message("files.read_file", {"path": "/home/x"}))[0]
        assert allowed["result"]["isError"] is False
        log.close()

    def test_policy_rules_use_the_unprefixed_tool_name(self) -> None:
        policy = Policy(rules=(Rule(id="r", effect=Effect.ALLOW, servers=("files",), tools=("read_file",)),))
        proxy, log = build_proxy({"files": FakeUpstream("files")}, policy)
        assert proxy.handle_message(call_message("files.read_file"))[0]["result"]["isError"] is False
        log.close()

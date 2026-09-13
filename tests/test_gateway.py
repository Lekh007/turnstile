from __future__ import annotations

from typing import Any

from turnstile.audit import AuditLog
from turnstile.budget import Budget, BudgetLedger
from turnstile.domain import Effect, Outcome, Principal
from turnstile.gateway import Gateway
from turnstile.mcp import CLIENT_CAPABILITIES_KEY, INVALID_PARAMS, PROTOCOL_VERSION_KEY
from turnstile.policy import ArgumentPredicate, Policy, Rule

PRINCIPAL = Principal(tenant="acme", subject="agent-1", scopes=("read",))


def request(tool: str = "read_file", arguments: dict[str, Any] | None = None, *, meta: bool = True) -> dict[str, Any]:
    params: dict[str, Any] = {"name": tool, "arguments": arguments or {}}
    if meta:
        params["_meta"] = {PROTOCOL_VERSION_KEY: "2026-07-28", CLIENT_CAPABILITIES_KEY: {}}
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}


class RecordingTransport:
    """Records what actually reached upstream, so 'never forwarded' is testable."""

    def __init__(self, result: dict[str, Any] | None = None, *, fail: bool = False) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._result = result or {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete", "content": []}}
        self._fail = fail

    def call(self, server: str, message: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((server, message))
        if self._fail:
            raise ConnectionError("upstream unreachable")
        return self._result


def build(policy: Policy, transport: RecordingTransport, **kwargs: Any) -> tuple[Gateway, AuditLog]:
    log = AuditLog()
    return Gateway(policy=policy, transport=transport, audit_log=log, **kwargs), log


ALLOW_ALL = Policy(rules=(Rule(id="allow-all", effect=Effect.ALLOW),))


class TestDenial:
    def test_denied_call_never_reaches_upstream(self) -> None:
        transport = RecordingTransport()
        gateway, log = build(Policy(), transport)  # empty policy => default deny
        result = gateway.handle("files", request(), PRINCIPAL)
        assert result.outcome is Outcome.DENIED
        assert transport.calls == [], "a denied call must never be forwarded"
        log.close()

    def test_denial_is_a_result_with_is_error_not_a_jsonrpc_error(self) -> None:
        # The spec reserves nearby error codes, and clients SHOULD hand tool
        # execution errors to the model so it can adapt. A refusal must also not
        # be confusable with a transport failure.
        gateway, log = build(Policy(), RecordingTransport())
        response = gateway.handle("files", request(), PRINCIPAL).response
        assert "error" not in response
        assert response["result"]["isError"] is True
        assert response["result"]["resultType"] == "complete"
        log.close()

    def test_denial_names_the_rule_so_an_agent_can_stop_retrying(self) -> None:
        policy = Policy(rules=(Rule(id="no-writes", effect=Effect.DENY, description="Writes are off limits."),))
        gateway, log = build(policy, RecordingTransport())
        text = gateway.handle("files", request("write_file"), PRINCIPAL).response["result"]["content"][0]["text"]
        assert "no-writes" in text
        assert "Writes are off limits." in text
        log.close()

    def test_denial_is_audited(self) -> None:
        gateway, log = build(Policy(), RecordingTransport())
        gateway.handle("files", request(), PRINCIPAL)
        records = list(log.records())
        assert len(records) == 1
        assert records[0].outcome is Outcome.DENIED
        assert records[0].effect is Effect.DENY
        log.close()


class TestApproval:
    def test_held_call_is_not_forwarded(self) -> None:
        policy = Policy(rules=(Rule(id="hold", effect=Effect.REQUIRE_APPROVAL, description="Needs a human."),))
        transport = RecordingTransport()
        gateway, log = build(policy, transport)
        result = gateway.handle("files", request(), PRINCIPAL)
        assert result.outcome is Outcome.AWAITING_APPROVAL
        assert transport.calls == []
        assert list(log.records())[0].outcome is Outcome.AWAITING_APPROVAL
        log.close()


class TestAllow:
    def test_allowed_call_is_forwarded_and_result_returned_verbatim(self) -> None:
        upstream = {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete", "content": [], "isError": False}}
        transport = RecordingTransport(upstream)
        gateway, log = build(ALLOW_ALL, transport)
        result = gateway.handle("files", request(), PRINCIPAL)
        assert result.outcome is Outcome.COMPLETED
        assert result.response == upstream
        assert len(transport.calls) == 1
        log.close()

    def test_completed_call_records_a_result_digest_not_the_payload(self) -> None:
        upstream = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "sensitive value"}]}}
        gateway, log = build(ALLOW_ALL, RecordingTransport(upstream))
        gateway.handle("files", request(), PRINCIPAL)
        record = list(log.records())[0]
        assert record.result_digest is not None
        assert len(record.result_digest) == 64
        assert "sensitive value" not in str(record.model_dump())
        log.close()

    def test_duration_is_recorded(self) -> None:
        ticks = iter([100.0, 100.25])
        gateway, log = build(ALLOW_ALL, RecordingTransport(), clock=lambda: next(ticks))
        gateway.handle("files", request(), PRINCIPAL)
        assert list(log.records())[0].duration_ms == 250.0
        log.close()


class TestUpstreamFailure:
    def test_transport_failure_is_audited_as_failed_not_denied(self) -> None:
        # An operator asking "what did we block?" must not be handed outages.
        gateway, log = build(ALLOW_ALL, RecordingTransport(fail=True))
        result = gateway.handle("files", request(), PRINCIPAL)
        assert result.outcome is Outcome.FAILED
        record = list(log.records())[0]
        assert record.outcome is Outcome.FAILED
        assert record.effect is Effect.ALLOW, "policy allowed it; the upstream is what failed"
        log.close()

    def test_transport_failure_returns_an_internal_error(self) -> None:
        gateway, log = build(ALLOW_ALL, RecordingTransport(fail=True))
        response = gateway.handle("files", request(), PRINCIPAL).response
        assert response["error"]["code"] == -32603
        log.close()


class TestMalformedRequests:
    def test_missing_meta_is_rejected_with_invalid_params(self) -> None:
        gateway, log = build(ALLOW_ALL, RecordingTransport())
        result = gateway.handle("files", request(meta=False), PRINCIPAL)
        assert result.response["error"]["code"] == INVALID_PARAMS
        assert result.audited is False, "there is no validated call to describe in the log"
        assert list(log.records()) == []
        log.close()

    def test_partial_meta_is_rejected(self) -> None:
        message = request()
        del message["params"]["_meta"][CLIENT_CAPABILITIES_KEY]
        gateway, log = build(ALLOW_ALL, RecordingTransport())
        response = gateway.handle("files", message, PRINCIPAL).response
        assert response["error"]["code"] == INVALID_PARAMS
        assert CLIENT_CAPABILITIES_KEY in response["error"]["message"]
        log.close()

    def test_malformed_request_never_reaches_upstream(self) -> None:
        transport = RecordingTransport()
        gateway, log = build(ALLOW_ALL, transport)
        gateway.handle("files", request(meta=False), PRINCIPAL)
        assert transport.calls == []
        log.close()


class TestBudget:
    def test_budget_stops_the_call_that_would_exceed_it(self) -> None:
        transport = RecordingTransport()
        ledger = BudgetLedger()
        gateway, log = build(ALLOW_ALL, transport, budget=Budget(max_calls=2), ledger=ledger)

        assert gateway.handle("files", request(), PRINCIPAL).outcome is Outcome.COMPLETED
        assert gateway.handle("files", request(), PRINCIPAL).outcome is Outcome.COMPLETED
        third = gateway.handle("files", request(), PRINCIPAL)

        assert third.outcome is Outcome.OVER_BUDGET
        assert len(transport.calls) == 2, "the over-budget call must not be forwarded"
        log.close()

    def test_denied_calls_do_not_consume_budget(self) -> None:
        # Otherwise a caller could exhaust a tenant's ceiling using calls they
        # were never permitted to make in the first place.
        policy = Policy(
            rules=(
                Rule(id="deny-writes", effect=Effect.DENY, tools=("write_*",)),
                Rule(id="allow-reads", effect=Effect.ALLOW, tools=("read_*",)),
            )
        )
        transport = RecordingTransport()
        gateway, log = build(policy, transport, budget=Budget(max_calls=1))

        for _ in range(5):
            gateway.handle("files", request("write_file"), PRINCIPAL)
        assert gateway.handle("files", request("read_file"), PRINCIPAL).outcome is Outcome.COMPLETED
        log.close()

    def test_failed_calls_do_not_consume_budget(self) -> None:
        # A flapping upstream must not burn a ceiling that exists for cost.
        transport = RecordingTransport(fail=True)
        ledger = BudgetLedger()
        gateway, log = build(ALLOW_ALL, transport, budget=Budget(max_calls=1), ledger=ledger)
        gateway.handle("files", request(), PRINCIPAL)
        assert ledger.calls_for("acme") == 0
        log.close()

    def test_per_tool_limit_is_independent_of_the_overall_limit(self) -> None:
        ledger = BudgetLedger()
        gateway, log = build(
            ALLOW_ALL, RecordingTransport(), budget=Budget(max_calls=10, max_calls_per_tool={"expensive": 1}), ledger=ledger
        )
        assert gateway.handle("files", request("expensive"), PRINCIPAL).outcome is Outcome.COMPLETED
        assert gateway.handle("files", request("expensive"), PRINCIPAL).outcome is Outcome.OVER_BUDGET
        assert gateway.handle("files", request("cheap"), PRINCIPAL).outcome is Outcome.COMPLETED
        log.close()

    def test_budgets_are_per_tenant(self) -> None:
        gateway, log = build(ALLOW_ALL, RecordingTransport(), budget=Budget(max_calls=1))
        other = Principal(tenant="globex", subject="agent-2")
        assert gateway.handle("files", request(), PRINCIPAL).outcome is Outcome.COMPLETED
        assert gateway.handle("files", request(), PRINCIPAL).outcome is Outcome.OVER_BUDGET
        assert gateway.handle("files", request(), other).outcome is Outcome.COMPLETED
        log.close()


class TestEveryPathIsAudited:
    def test_all_governed_outcomes_produce_exactly_one_record(self) -> None:
        # A governance log with holes where refusals belong is worse than no
        # log, because it looks complete.
        policy = Policy(
            rules=(
                Rule(id="deny", effect=Effect.DENY, tools=("denied",)),
                Rule(id="hold", effect=Effect.REQUIRE_APPROVAL, tools=("held",)),
                Rule(id="allow", effect=Effect.ALLOW),
            )
        )
        gateway, log = build(policy, RecordingTransport(), budget=Budget(max_calls_per_tool={"capped": 0}))

        gateway.handle("files", request("denied"), PRINCIPAL)
        gateway.handle("files", request("held"), PRINCIPAL)
        gateway.handle("files", request("capped"), PRINCIPAL)
        gateway.handle("files", request("fine"), PRINCIPAL)

        outcomes = [record.outcome for record in log.records()]
        assert outcomes == [
            Outcome.DENIED,
            Outcome.AWAITING_APPROVAL,
            Outcome.OVER_BUDGET,
            Outcome.COMPLETED,
        ]
        assert log.verify() == 4
        log.close()

    def test_argument_predicates_apply_end_to_end(self) -> None:
        policy = Policy(
            rules=(
                Rule(
                    id="no-drop",
                    effect=Effect.DENY,
                    description="Destructive SQL is not delegated to agents.",
                    arguments=(ArgumentPredicate(path="query", operator="regex", value=r"(?i)\bdrop\b"),),
                ),
                Rule(id="allow", effect=Effect.ALLOW),
            )
        )
        transport = RecordingTransport()
        gateway, log = build(policy, transport)

        denied = gateway.handle("db", request("execute_sql", {"query": "DROP TABLE users"}), PRINCIPAL)
        allowed = gateway.handle("db", request("execute_sql", {"query": "SELECT 1"}), PRINCIPAL)

        assert denied.outcome is Outcome.DENIED
        assert allowed.outcome is Outcome.COMPLETED
        assert len(transport.calls) == 1
        log.close()

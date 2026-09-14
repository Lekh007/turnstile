from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from turnstile.approvals import ApprovalError, ApprovalState, ApprovalStore, call_digest
from turnstile.audit import AuditLog
from turnstile.budget import BudgetLedger
from turnstile.domain import Effect, Outcome, Principal, ToolCall
from turnstile.gateway import Gateway
from turnstile.mcp import CLIENT_CAPABILITIES_KEY, PROTOCOL_VERSION_KEY
from turnstile.policy import Policy, Rule

REQUESTER = Principal(tenant="acme", subject="agent-for-priya")
APPROVER = "dana"


def call(tool: str = "delete_file", arguments: dict[str, Any] | None = None, *, tenant: str = "acme") -> ToolCall:
    return ToolCall(
        server="files",
        tool=tool,
        arguments=arguments if arguments is not None else {"path": "/tmp/scratch"},
        principal=Principal(tenant=tenant, subject=REQUESTER.subject),
    )


def request_message(tool: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": arguments if arguments is not None else {"path": "/tmp/scratch"},
            "_meta": {PROTOCOL_VERSION_KEY: "2026-07-28", CLIENT_CAPABILITIES_KEY: {}},
        },
    }


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, server: str, message: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((server, message))
        return {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete", "content": [], "isError": False}}


class TestBinding:
    """An approval covers one call, not a standing permission."""

    def test_approval_does_not_cover_different_arguments(self) -> None:
        # The whole point: approving "delete /tmp/scratch" must never authorise
        # "delete /etc/passwd".
        store = ApprovalStore()
        pending = store.request(call(arguments={"path": "/tmp/scratch"}), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)

        assert store.consume(call(arguments={"path": "/etc/passwd"})) is None
        assert store.consume(call(arguments={"path": "/tmp/scratch"})) is not None

    def test_approval_does_not_cover_a_different_tool(self) -> None:
        store = ApprovalStore()
        pending = store.request(call(tool="delete_file"), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)
        assert store.consume(call(tool="delete_directory")) is None

    def test_approval_does_not_cross_tenants(self) -> None:
        store = ApprovalStore()
        pending = store.request(call(tenant="acme"), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)
        assert store.consume(call(tenant="globex")) is None

    def test_digest_ignores_argument_ordering(self) -> None:
        a = call(arguments={"path": "/x", "force": True})
        b = call(arguments={"force": True, "path": "/x"})
        assert call_digest(a) == call_digest(b)

    def test_digest_ignores_the_requester(self) -> None:
        # So a granted approval survives the requester retrying it.
        one = ToolCall(server="files", tool="delete_file", arguments={"path": "/x"},
                       principal=Principal(tenant="acme", subject="a"))
        two = ToolCall(server="files", tool="delete_file", arguments={"path": "/x"},
                       principal=Principal(tenant="acme", subject="b"))
        assert call_digest(one) == call_digest(two)


class TestSingleUse:
    def test_an_approval_is_spent_when_used(self) -> None:
        # Otherwise one approved deletion authorises unlimited deletions.
        store = ApprovalStore()
        pending = store.request(call(), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)

        assert store.consume(call()) is not None
        assert store.consume(call()) is None

    def test_consumed_approval_is_marked_consumed(self) -> None:
        store = ApprovalStore()
        pending = store.request(call(), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)
        store.consume(call())
        record = store.get(pending.id)
        assert record is not None and record.state is ApprovalState.CONSUMED


class TestSeparationOfDuties:
    def test_the_requester_cannot_approve_their_own_request(self) -> None:
        # Without this, "ask a human" collapses into the agent asking itself,
        # since the agent acts as the requesting human.
        store = ApprovalStore()
        pending = store.request(call(), arguments_redacted={})
        with pytest.raises(ApprovalError, match="may not also approve"):
            store.decide(pending.id, approver=REQUESTER.subject, approve=True)

    def test_someone_else_can_approve(self) -> None:
        store = ApprovalStore()
        pending = store.request(call(), arguments_redacted={})
        decided = store.decide(pending.id, approver=APPROVER, approve=True)
        assert decided.state is ApprovalState.APPROVED
        assert decided.decided_by == APPROVER


class TestExpiryAndRejection:
    def test_an_expired_approval_cannot_be_used(self) -> None:
        store = ApprovalStore(ttl_seconds=0)
        pending = store.request(call(), arguments_redacted={})
        with pytest.raises(ApprovalError, match="expired"):
            store.decide(pending.id, approver=APPROVER, approve=True)

    def test_an_approval_that_expires_after_granting_cannot_be_consumed(self, tmp_path) -> None:
        store = ApprovalStore(tmp_path / "queue.sqlite3", ttl_seconds=120)
        pending = store.request(call(), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)
        # Force expiry without sleeping: rewind the stored expiry into the
        # past, which is exactly the row the clock would have changed.
        with sqlite3.connect(tmp_path / "queue.sqlite3") as conn:
            conn.execute("UPDATE approvals SET expires_at = ?", (pending.requested_at.isoformat(),))
        assert store.consume(call()) is None

    def test_a_rejected_request_is_not_consumable(self) -> None:
        store = ApprovalStore()
        pending = store.request(call(), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=False, reason="not in scope")
        assert store.consume(call()) is None

    def test_deciding_twice_is_refused(self) -> None:
        store = ApprovalStore()
        pending = store.request(call(), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)
        with pytest.raises(ApprovalError, match="already"):
            store.decide(pending.id, approver=APPROVER, approve=False)

    def test_unknown_id_is_refused(self) -> None:
        with pytest.raises(ApprovalError, match="no such approval"):
            ApprovalStore().decide("nope", approver=APPROVER, approve=True)

    def test_ids_are_unguessable(self) -> None:
        store = ApprovalStore()
        ids = {store.request(call(arguments={"path": f"/tmp/{n}"}), arguments_redacted={}).id for n in range(25)}
        assert len(ids) == 25
        assert all(len(identifier) >= 16 for identifier in ids)


class TestThroughTheGateway:
    @staticmethod
    def build() -> tuple[Gateway, AuditLog, ApprovalStore, RecordingTransport]:
        policy = Policy(
            redact_paths=("credentials.token",),
            rules=(
                Rule(id="deletes-need-a-human", effect=Effect.REQUIRE_APPROVAL,
                     description="Deleting is not delegated.", tools=("delete_file",)),
                Rule(id="allow-rest", effect=Effect.ALLOW),
            ),
        )
        store = ApprovalStore()
        transport = RecordingTransport()
        log = AuditLog()
        gateway = Gateway(policy=policy, transport=transport, audit_log=log,
                          approvals=store, ledger=BudgetLedger())
        return gateway, log, store, transport

    def test_held_call_is_not_forwarded_and_returns_an_approval_id(self) -> None:
        gateway, log, store, transport = self.build()
        result = gateway.handle("files", request_message("delete_file"), REQUESTER)
        assert result.outcome is Outcome.AWAITING_APPROVAL
        assert transport.calls == []
        text = result.response["result"]["content"][0]["text"]
        pending = store.pending()
        assert len(pending) == 1
        assert pending[0].id in text
        log.close()

    def test_after_approval_the_same_call_goes_through(self) -> None:
        gateway, log, store, transport = self.build()
        gateway.handle("files", request_message("delete_file"), REQUESTER)
        store.decide(store.pending()[0].id, approver=APPROVER, approve=True)

        second = gateway.handle("files", request_message("delete_file"), REQUESTER)
        assert second.outcome is Outcome.COMPLETED
        assert len(transport.calls) == 1
        log.close()

    def test_the_audit_log_records_who_approved_rather_than_a_rule(self) -> None:
        gateway, log, store, transport = self.build()
        gateway.handle("files", request_message("delete_file"), REQUESTER)
        approval_id = store.pending()[0].id
        store.decide(approval_id, approver=APPROVER, approve=True)
        gateway.handle("files", request_message("delete_file"), REQUESTER)

        records = list(log.records())
        assert records[0].outcome is Outcome.AWAITING_APPROVAL
        assert records[1].outcome is Outcome.COMPLETED
        assert records[1].rule_id == f"approval:{approval_id}"
        assert APPROVER in records[1].reason
        assert log.verify() == 2
        log.close()

    def test_approval_for_one_path_does_not_release_another(self) -> None:
        gateway, log, store, transport = self.build()
        gateway.handle("files", request_message("delete_file", {"path": "/tmp/ok"}), REQUESTER)
        store.decide(store.pending()[0].id, approver=APPROVER, approve=True)

        other = gateway.handle("files", request_message("delete_file", {"path": "/etc/passwd"}), REQUESTER)
        assert other.outcome is Outcome.AWAITING_APPROVAL
        assert transport.calls == []
        log.close()

    def test_a_second_execution_needs_a_second_approval(self) -> None:
        gateway, log, store, transport = self.build()
        gateway.handle("files", request_message("delete_file"), REQUESTER)
        store.decide(store.pending()[0].id, approver=APPROVER, approve=True)
        gateway.handle("files", request_message("delete_file"), REQUESTER)

        third = gateway.handle("files", request_message("delete_file"), REQUESTER)
        assert third.outcome is Outcome.AWAITING_APPROVAL
        assert len(transport.calls) == 1
        log.close()

    def test_pending_arguments_are_redacted(self) -> None:
        gateway, log, store, transport = self.build()
        gateway.handle(
            "files",
            request_message("delete_file", {"path": "/tmp/x", "credentials": {"token": "sk-live-SECRET"}}),
            REQUESTER,
        )
        assert "sk-live-SECRET" not in str(store.pending()[0].arguments_redacted)
        log.close()

    def test_without_an_approval_store_a_hold_is_still_a_hold(self) -> None:
        # Degrades to refusing, never to allowing.
        policy = Policy(rules=(Rule(id="hold", effect=Effect.REQUIRE_APPROVAL),))
        transport = RecordingTransport()
        log = AuditLog()
        gateway = Gateway(policy=policy, transport=transport, audit_log=log)
        assert gateway.handle("files", request_message("anything"), REQUESTER).outcome is Outcome.AWAITING_APPROVAL
        assert transport.calls == []
        log.close()


class TestDurability:
    """The queue survives the process that created it.

    A hold outliving a gateway restart is the entire point of persistence:
    a human can decide while the gateway is down, and the agent's next retry
    finds the decision waiting. Expiry is the only thing that clears a live
    hold -- never a restart.
    """

    def test_a_decision_survives_a_reopen(self, tmp_path):  # type: ignore[no-untyped-def]
        store = ApprovalStore(tmp_path / "queue.sqlite3")
        pending = store.request(call(arguments={"path": "/tmp/scratch"}), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True, reason="checked the path")
        store.close()

        reopened = ApprovalStore(tmp_path / "queue.sqlite3")
        decided = reopened.get(pending.id)
        assert decided is not None
        assert decided.state is ApprovalState.APPROVED
        assert decided.decided_by == APPROVER
        assert decided.reason == "checked the path"
        assert reopened.consume(call(arguments={"path": "/tmp/scratch"})) is not None
        reopened.close()

    def test_a_pending_hold_survives_a_reopen_and_can_still_be_decided(self, tmp_path):  # type: ignore[no-untyped-def]
        store = ApprovalStore(tmp_path / "queue.sqlite3")
        pending = store.request(call(), arguments_redacted={"path": "/tmp/scratch"})
        store.close()

        reopened = ApprovalStore(tmp_path / "queue.sqlite3")
        live = reopened.pending()
        assert [p.id for p in live] == [pending.id]

        reopened.decide(pending.id, approver=APPROVER, approve=True)
        assert reopened.consume(call()) is not None
        reopened.close()

    def test_consumption_is_single_use_across_a_reopen(self, tmp_path):  # type: ignore[no-untyped-def]
        store = ApprovalStore(tmp_path / "queue.sqlite3")
        pending = store.request(call(), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)
        store.close()

        first = ApprovalStore(tmp_path / "queue.sqlite3")
        assert first.consume(call()) is not None
        assert first.consume(call()) is None
        first.close()

        second = ApprovalStore(tmp_path / "queue.sqlite3")
        assert second.consume(call()) is None
        second.close()

    def test_self_approval_is_still_refused_on_a_durable_store(self, tmp_path):  # type: ignore[no-untyped-def]
        store = ApprovalStore(tmp_path / "queue.sqlite3")
        pending = store.request(call(), arguments_redacted={})
        with pytest.raises(ApprovalError, match="may not also approve"):
            store.decide(pending.id, approver=REQUESTER.subject, approve=True)
        store.close()

    def test_an_expired_hold_is_not_revived_by_a_reopen(self, tmp_path):  # type: ignore[no-untyped-def]
        store = ApprovalStore(tmp_path / "queue.sqlite3", ttl_seconds=0)
        store.request(call(), arguments_redacted={})
        store.close()

        reopened = ApprovalStore(tmp_path / "queue.sqlite3", ttl_seconds=0)
        assert reopened.pending() == []
        assert reopened.consume(call()) is None
        reopened.close()

    def test_purge_marks_expired_holds_without_losing_them(self, tmp_path):  # type: ignore[no-untyped-def]
        store = ApprovalStore(tmp_path / "queue.sqlite3", ttl_seconds=0)
        pending = store.request(call(), arguments_redacted={})
        assert store.purge_expired() >= 1
        assert store.purge_expired() == 0  # already EXPIRED: nothing left to sweep

        swept = store.get(pending.id)
        assert swept is not None and swept.state is ApprovalState.EXPIRED
        store.close()

    def test_approvals_share_the_audit_file_without_touching_the_chain(self, tmp_path):  # type: ignore[no-untyped-def]
        # The console plan's architecture: one store file, two tables. Approval
        # writes must leave the hash chain exactly as verifiable as before.
        path = tmp_path / "turnstile.sqlite3"
        log = AuditLog(path)
        store = ApprovalStore(path)

        pending = store.request(call(), arguments_redacted={})
        store.decide(pending.id, approver=APPROVER, approve=True)
        assert store.consume(call()) is not None

        assert log.verify() == 0  # empty chain, still intact
        log.close()
        store.close()

        # Reopening both over the same file keeps working.
        log_again = AuditLog(path)
        store_again = ApprovalStore(path)
        assert log_again.verify() == 0
        assert store_again.pending() == []
        log_again.close()
        store_again.close()

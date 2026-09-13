from __future__ import annotations

import pytest

from turnstile.audit import GENESIS_DIGEST, AuditLog, ChainBroken, redact
from turnstile.domain import Decision, Effect, Outcome, Principal, ToolCall


def call(*, tenant: str = "acme", tool: str = "read", arguments: dict[str, object] | None = None) -> ToolCall:
    return ToolCall(
        server="files",
        tool=tool,
        arguments=arguments or {},
        principal=Principal(tenant=tenant, subject="agent-1"),
    )


ALLOWED = Decision(effect=Effect.ALLOW, rule_id="r", reason="ok")


class TestRedaction:
    def test_redacts_a_nested_path(self) -> None:
        out = redact({"credentials": {"token": "sk-secret", "user": "bob"}}, ["credentials.token"])
        assert out["credentials"]["token"] == "[redacted]"
        assert out["credentials"]["user"] == "bob"

    def test_does_not_mutate_the_input(self) -> None:
        # The caller still has to forward the real arguments upstream. A
        # redactor that destroys them breaks the call it was protecting.
        original = {"credentials": {"token": "sk-secret"}}
        redact(original, ["credentials.token"])
        assert original["credentials"]["token"] == "sk-secret"

    def test_unknown_path_is_not_an_error(self) -> None:
        assert redact({"a": 1}, ["does.not.exist"]) == {"a": 1}

    def test_redacts_inside_lists(self) -> None:
        out = redact({"items": [{"key": "secret"}]}, ["items.0.key"])
        assert out["items"][0]["key"] == "[redacted]"

    def test_secret_never_reaches_the_log(self) -> None:
        with AuditLog() as log:
            log.append(
                call=call(arguments={"credentials": {"token": "sk-live-DEADBEEF"}}),
                decision=ALLOWED,
                outcome=Outcome.COMPLETED,
                redact_paths=["credentials.token"],
            )
            stored = list(log.records())[0]
        assert "sk-live-DEADBEEF" not in str(stored.arguments_redacted)
        assert stored.arguments_redacted["credentials"]["token"] == "[redacted]"


class TestChain:
    def test_empty_log_verifies_and_heads_at_genesis(self) -> None:
        with AuditLog() as log:
            assert log.verify() == 0
            assert log.head_digest() == GENESIS_DIGEST

    def test_first_record_links_to_genesis(self) -> None:
        with AuditLog() as log:
            record = log.append(call=call(), decision=ALLOWED, outcome=Outcome.COMPLETED)
            assert record.previous_digest == GENESIS_DIGEST
            assert record.sequence == 0

    def test_each_record_links_to_the_one_before(self) -> None:
        with AuditLog() as log:
            first = log.append(call=call(), decision=ALLOWED, outcome=Outcome.COMPLETED)
            second = log.append(call=call(), decision=ALLOWED, outcome=Outcome.COMPLETED)
            assert second.previous_digest == first.digest
            assert log.verify() == 2

    def test_tampering_with_content_breaks_verification(self) -> None:
        with AuditLog() as log:
            log.append(call=call(), decision=ALLOWED, outcome=Outcome.DENIED)
            log.append(call=call(), decision=ALLOWED, outcome=Outcome.COMPLETED)
            # Rewrite a refusal into a success, exactly what someone covering
            # their tracks would do.
            log._connection.execute("UPDATE audit SET outcome = 'completed' WHERE sequence = 0")
            with pytest.raises(ChainBroken) as excinfo:
                log.verify()
        assert excinfo.value.sequence == 0
        assert "digest" in excinfo.value.detail

    def test_deleting_a_record_breaks_verification(self) -> None:
        with AuditLog() as log:
            for _ in range(3):
                log.append(call=call(), decision=ALLOWED, outcome=Outcome.COMPLETED)
            log._connection.execute("DELETE FROM audit WHERE sequence = 1")
            with pytest.raises(ChainBroken) as excinfo:
                log.verify()
        # Sequence 2 is now where sequence 1 should be: the gap is detected.
        assert excinfo.value.sequence == 2

    def test_digest_is_reproducible_from_stored_content(self) -> None:
        # An auditor must be able to recompute digests independently; if the
        # digest depended on dict ordering this would be flaky.
        with AuditLog() as log:
            log.append(call=call(arguments={"b": 2, "a": 1}), decision=ALLOWED, outcome=Outcome.COMPLETED)
            assert log.verify() == 1


class TestTenantIsolation:
    def test_records_are_scoped_to_one_tenant(self) -> None:
        with AuditLog() as log:
            log.append(call=call(tenant="acme"), decision=ALLOWED, outcome=Outcome.COMPLETED)
            log.append(call=call(tenant="globex"), decision=ALLOWED, outcome=Outcome.COMPLETED)
            log.append(call=call(tenant="acme"), decision=ALLOWED, outcome=Outcome.COMPLETED)

            acme = list(log.records(tenant="acme"))
            globex = list(log.records(tenant="globex"))

        assert len(acme) == 2
        assert len(globex) == 1
        assert {record.tenant for record in acme} == {"acme"}
        assert {record.tenant for record in globex} == {"globex"}

    def test_one_tenant_cannot_see_another_tenants_arguments(self) -> None:
        with AuditLog() as log:
            log.append(
                call=call(tenant="globex", arguments={"path": "/globex/secret-plan.txt"}),
                decision=ALLOWED,
                outcome=Outcome.COMPLETED,
            )
            log.append(call=call(tenant="acme"), decision=ALLOWED, outcome=Outcome.COMPLETED)
            visible = str([record.model_dump() for record in log.records(tenant="acme")])
        assert "secret-plan" not in visible

    def test_the_chain_still_verifies_across_tenants(self) -> None:
        # Isolation is a read-time filter; the chain itself spans all tenants so
        # that a deletion cannot be hidden by scoping a query.
        with AuditLog() as log:
            log.append(call=call(tenant="acme"), decision=ALLOWED, outcome=Outcome.COMPLETED)
            log.append(call=call(tenant="globex"), decision=ALLOWED, outcome=Outcome.COMPLETED)
            assert log.verify() == 2

from __future__ import annotations

from pathlib import Path

import pytest

from turnstile.audit import (
    GENESIS_DIGEST,
    IN_MEMORY,
    AuditLog,
    AuditUnavailable,
    ChainBroken,
    redact,
)
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


class TestOpeningTheLog:
    """A clean clone must be able to run the documented command.

    These exist because `pytest` was green while `turnstile --config
    examples/turnstile.json verify` died with a raw sqlite traceback on a fresh
    checkout: every test used the in-memory default, so no test ever opened a
    file at a path whose directory did not exist yet.
    """

    def test_a_missing_parent_directory_is_created(self, tmp_path: Path) -> None:
        path = tmp_path / "does" / "not" / "exist" / "audit.sqlite3"
        assert not path.parent.exists()
        with AuditLog(path) as log:
            assert log.verify() == 0
        assert path.exists()

    def test_the_example_config_path_works_from_a_clean_checkout(self, tmp_path: Path) -> None:
        # The exact shape shipped in examples/turnstile.json: a relative path
        # under a dot-directory that a fresh clone does not contain.
        path = tmp_path / ".turnstile" / "audit.sqlite3"
        with AuditLog(path) as log:
            log.append(call=call(), decision=ALLOWED, outcome=Outcome.COMPLETED)
        with AuditLog(path) as reopened:
            assert reopened.verify() == 1, "the chain must survive a reopen"

    def test_in_memory_is_never_treated_as_a_filename(self, tmp_path: Path) -> None:
        # Creating a ':memory:' directory on disk would be a silent, confusing
        # side effect of the default configuration.
        before = set(tmp_path.iterdir())
        with AuditLog(IN_MEMORY) as log:
            assert log.verify() == 0
        assert set(tmp_path.iterdir()) == before

    def test_an_unwritable_path_is_reported_against_the_setting(self, tmp_path: Path) -> None:
        # A file where a directory needs to be: the operator gets the setting
        # name and the remedy, not a sqlite error code.
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        with pytest.raises(AuditUnavailable) as caught:
            AuditLog(blocker / "nested" / "audit.sqlite3")
        message = str(caught.value)
        assert "audit_path" in message
        assert IN_MEMORY in message

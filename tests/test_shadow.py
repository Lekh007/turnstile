from __future__ import annotations

from typing import Any

from turnstile.audit import AuditLog
from turnstile.domain import Decision, Effect, Outcome, Principal, ToolCall
from turnstile.policy import ArgumentPredicate, Policy, Rule
from turnstile.shadow import replay

ALLOWED = Decision(effect=Effect.ALLOW, rule_id="allow-all", reason="permitted")


def record_call(
    log: AuditLog,
    tool: str,
    arguments: dict[str, Any] | None = None,
    *,
    decision: Decision = ALLOWED,
    outcome: Outcome = Outcome.COMPLETED,
    redact_paths: tuple[str, ...] = (),
) -> None:
    log.append(
        call=ToolCall(
            server="files",
            tool=tool,
            arguments=arguments or {},
            principal=Principal(tenant="acme", subject="agent-1"),
        ),
        decision=decision,
        outcome=outcome,
        redact_paths=redact_paths,
    )


ALLOW_ALL = Policy(rules=(Rule(id="allow-all", effect=Effect.ALLOW),))


class TestReplay:
    def test_an_identical_policy_changes_nothing(self) -> None:
        with AuditLog() as log:
            for tool in ("read_file", "list_dir", "write_file"):
                record_call(log, tool)
            report = replay(ALLOW_ALL, log.records())
        assert report.evaluated == 3
        assert report.unchanged == 3
        assert report.changed == 0

    def test_a_tightened_policy_reports_what_it_would_newly_block(self) -> None:
        with AuditLog() as log:
            record_call(log, "read_file")
            record_call(log, "delete_file")
            record_call(log, "delete_file")
            candidate = Policy(
                rules=(
                    Rule(id="no-deletes", effect=Effect.DENY, tools=("delete_*",)),
                    Rule(id="allow-rest", effect=Effect.ALLOW),
                )
            )
            report = replay(candidate, log.records())

        assert len(report.newly_denied) == 2
        assert {change.tool for change in report.newly_denied} == {"delete_file"}
        assert report.unchanged == 1
        assert all(change.after_rule == "no-deletes" for change in report.newly_denied)

    def test_a_loosened_policy_reports_what_it_would_newly_allow(self) -> None:
        denied = Decision(effect=Effect.DENY, rule_id="old-deny", reason="was blocked")
        with AuditLog() as log:
            record_call(log, "read_file", decision=denied, outcome=Outcome.DENIED)
            report = replay(ALLOW_ALL, log.records())
        assert len(report.newly_allowed) == 1
        assert report.newly_allowed[0].before is Effect.DENY

    def test_newly_held_calls_are_reported_separately_from_denied(self) -> None:
        # "Needs a human" and "never" are different operational outcomes.
        with AuditLog() as log:
            record_call(log, "delete_file")
            candidate = Policy(
                rules=(
                    Rule(id="hold-deletes", effect=Effect.REQUIRE_APPROVAL, tools=("delete_*",)),
                    Rule(id="allow-rest", effect=Effect.ALLOW),
                )
            )
            report = replay(candidate, log.records())
        assert len(report.newly_held) == 1
        assert report.newly_denied == []

    def test_default_deny_shows_up_when_a_candidate_omits_a_rule(self) -> None:
        with AuditLog() as log:
            record_call(log, "read_file")
            report = replay(Policy(), log.records())
        assert len(report.newly_denied) == 1
        assert report.newly_denied[0].after_rule == "<implicit-default-deny>"

    def test_comparing_against_a_current_policy_rather_than_history(self) -> None:
        with AuditLog() as log:
            record_call(log, "read_file")
            current = Policy(rules=(Rule(id="deny-everything", effect=Effect.DENY),))
            report = replay(ALLOW_ALL, log.records(), current=current)
        # History says it was allowed, but the *current* policy would deny it,
        # so the candidate is a loosening relative to current.
        assert len(report.newly_allowed) == 1
        assert report.newly_allowed[0].before_rule == "deny-everything"

    def test_rule_hits_show_which_rules_actually_fire(self) -> None:
        with AuditLog() as log:
            record_call(log, "read_file")
            record_call(log, "read_file")
            record_call(log, "delete_file")
            candidate = Policy(
                rules=(
                    Rule(id="no-deletes", effect=Effect.DENY, tools=("delete_*",)),
                    Rule(id="allow-reads", effect=Effect.ALLOW, tools=("read_*",)),
                    Rule(id="never-matches", effect=Effect.ALLOW, tools=("nothing_like_this",)),
                )
            )
            report = replay(candidate, log.records())
        assert report.rule_hits["allow-reads"] == 2
        assert report.rule_hits["no-deletes"] == 1
        assert report.rule_hits["never-matches"] == 0


class TestRedactionHonesty:
    """The limitation that has to be reported rather than guessed around."""

    def test_a_rule_reading_a_redacted_path_is_unevaluable(self) -> None:
        # The value the rule needs was deliberately never written down, so the
        # only honest answer is "cannot tell".
        with AuditLog() as log:
            record_call(
                log,
                "execute_sql",
                {"credentials": {"token": "sk-live-SECRET"}, "query": "SELECT 1"},
                redact_paths=("credentials.token",),
            )
            candidate = Policy(
                rules=(
                    Rule(
                        id="block-a-specific-token",
                        effect=Effect.DENY,
                        arguments=(ArgumentPredicate(path="credentials.token", operator="equals",
                                                     value="sk-live-SECRET"),),
                    ),
                    Rule(id="allow-rest", effect=Effect.ALLOW),
                )
            )
            report = replay(candidate, log.records())

        assert report.unevaluable == [0]
        assert report.evaluated == 0
        assert report.changed == 0, "an unevaluable record must not be counted as a change"

    def test_a_rule_reading_an_unredacted_path_is_still_evaluable(self) -> None:
        with AuditLog() as log:
            record_call(
                log,
                "execute_sql",
                {"credentials": {"token": "sk"}, "query": "DROP TABLE t"},
                redact_paths=("credentials.token",),
            )
            candidate = Policy(
                rules=(
                    Rule(id="no-drop", effect=Effect.DENY,
                         arguments=(ArgumentPredicate(path="query", operator="regex", value=r"(?i)\bdrop\b"),)),
                    Rule(id="allow-rest", effect=Effect.ALLOW),
                )
            )
            report = replay(candidate, log.records())
        assert report.unevaluable == []
        assert len(report.newly_denied) == 1

    def test_summary_mentions_unevaluable_records_when_present(self) -> None:
        with AuditLog() as log:
            record_call(log, "x", {"secret": "s"}, redact_paths=("secret",))
            candidate = Policy(
                rules=(Rule(id="r", effect=Effect.DENY,
                            arguments=(ArgumentPredicate(path="secret", operator="equals", value="s"),)),)
            )
            summary = replay(candidate, log.records()).summary()
        assert "unevaluable" in summary
        assert "redaction removed" in summary

    def test_summary_omits_the_unevaluable_line_when_there_are_none(self) -> None:
        with AuditLog() as log:
            record_call(log, "read_file")
            summary = replay(ALLOW_ALL, log.records()).summary()
        assert "unevaluable" not in summary


class TestEmptyHistory:
    def test_replaying_nothing_is_not_an_error(self) -> None:
        with AuditLog() as log:
            report = replay(ALLOW_ALL, log.records())
        assert report.evaluated == 0
        assert report.changed == 0
        assert "Evaluated 0" in report.summary()

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from turnstile.domain import Effect, Principal, ToolCall
from turnstile.policy import IMPLICIT_DEFAULT_RULE_ID, ArgumentPredicate, Policy, Rule


def call(
    *,
    server: str = "files",
    tool: str = "read",
    arguments: dict[str, Any] | None = None,
    tenant: str = "acme",
    scopes: tuple[str, ...] = (),
) -> ToolCall:
    return ToolCall(
        server=server,
        tool=tool,
        arguments=arguments or {},
        principal=Principal(tenant=tenant, subject="agent-1", scopes=scopes),
    )


class TestDefaultDeny:
    def test_empty_policy_denies(self) -> None:
        decision = Policy().evaluate(call())
        assert decision.effect is Effect.DENY
        assert decision.rule_id == IMPLICIT_DEFAULT_RULE_ID
        assert decision.matched_index is None

    def test_unmatched_call_denies_even_when_allow_rules_exist(self) -> None:
        policy = Policy(rules=(Rule(id="allow-reads", effect=Effect.ALLOW, tools=("read",)),))
        assert policy.evaluate(call(tool="delete")).effect is Effect.DENY

    def test_default_denial_names_the_call_so_an_operator_can_write_the_rule(self) -> None:
        decision = Policy().evaluate(call(server="db", tool="drop_table", tenant="globex"))
        assert "db/drop_table" in decision.reason
        assert "globex" in decision.reason


class TestOrdering:
    def test_first_match_wins_even_when_a_later_rule_would_also_match(self) -> None:
        policy = Policy(
            rules=(
                Rule(id="deny-writes", effect=Effect.DENY, tools=("write",)),
                Rule(id="allow-everything", effect=Effect.ALLOW),
            )
        )
        assert policy.evaluate(call(tool="write")).rule_id == "deny-writes"
        assert policy.evaluate(call(tool="read")).rule_id == "allow-everything"

    def test_reordering_the_same_rules_changes_the_outcome(self) -> None:
        deny = Rule(id="deny-writes", effect=Effect.DENY, tools=("write",))
        allow = Rule(id="allow-everything", effect=Effect.ALLOW)
        assert Policy(rules=(deny, allow)).evaluate(call(tool="write")).effect is Effect.DENY
        assert Policy(rules=(allow, deny)).evaluate(call(tool="write")).effect is Effect.ALLOW

    def test_matched_index_points_at_the_deciding_rule(self) -> None:
        policy = Policy(
            rules=(
                Rule(id="a", effect=Effect.ALLOW, tools=("nope",)),
                Rule(id="b", effect=Effect.ALLOW, tools=("nope-either",)),
                Rule(id="c", effect=Effect.ALLOW, tools=("read",)),
            )
        )
        assert policy.evaluate(call(tool="read")).matched_index == 2

    def test_duplicate_rule_ids_are_rejected_at_load(self) -> None:
        with pytest.raises(ValidationError, match="duplicate rule id"):
            Policy(rules=(Rule(id="same", effect=Effect.ALLOW), Rule(id="same", effect=Effect.DENY)))


class TestSelectors:
    def test_globs_match_servers_and_tools(self) -> None:
        policy = Policy(rules=(Rule(id="r", effect=Effect.ALLOW, servers=("prod-*",), tools=("read_*",)),))
        assert policy.evaluate(call(server="prod-files", tool="read_file")).is_allowed
        assert not policy.evaluate(call(server="staging-files", tool="read_file")).is_allowed
        assert not policy.evaluate(call(server="prod-files", tool="write_file")).is_allowed

    def test_glob_matching_is_case_sensitive(self) -> None:
        # fnmatchcase, not fnmatch: on a case-insensitive filesystem the latter
        # would make 'Read' match 'read' and silently widen every policy.
        policy = Policy(rules=(Rule(id="r", effect=Effect.ALLOW, tools=("read",)),))
        assert not policy.evaluate(call(tool="READ")).is_allowed

    def test_unset_selector_means_any(self) -> None:
        policy = Policy(rules=(Rule(id="r", effect=Effect.ALLOW),))
        assert policy.evaluate(call(server="anything", tool="whatever")).is_allowed

    def test_require_scopes_needs_every_listed_scope(self) -> None:
        policy = Policy(rules=(Rule(id="r", effect=Effect.ALLOW, require_scopes=("read", "admin")),))
        assert policy.evaluate(call(scopes=("read", "admin", "extra"))).is_allowed
        assert not policy.evaluate(call(scopes=("read",))).is_allowed

    def test_tenant_selector_isolates(self) -> None:
        policy = Policy(rules=(Rule(id="r", effect=Effect.ALLOW, tenants=("acme",)),))
        assert policy.evaluate(call(tenant="acme")).is_allowed
        assert not policy.evaluate(call(tenant="globex")).is_allowed


class TestArgumentPredicates:
    def test_dotted_path_walks_nested_objects(self) -> None:
        predicate = ArgumentPredicate(path="query.limit", operator="gt", value=100)
        assert predicate.matches({"query": {"limit": 500}})
        assert not predicate.matches({"query": {"limit": 10}})

    def test_numeric_index_walks_lists(self) -> None:
        predicate = ArgumentPredicate(path="files.0.path", operator="glob", value="/etc/*")
        assert predicate.matches({"files": [{"path": "/etc/passwd"}]})
        assert not predicate.matches({"files": [{"path": "/home/x"}]})

    def test_missing_path_never_matches_so_omission_cannot_bypass_a_deny(self) -> None:
        # The security property: a rule that denies when force==true must not be
        # evadable by simply not sending `force`. Absence is not satisfaction.
        predicate = ArgumentPredicate(path="force", operator="equals", value=True)
        assert not predicate.matches({})

    def test_absent_operator_matches_only_when_truly_missing(self) -> None:
        predicate = ArgumentPredicate(path="dry_run", operator="absent")
        assert predicate.matches({})
        assert not predicate.matches({"dry_run": False})

    def test_explicit_null_is_present_not_absent(self) -> None:
        # _resolve returns (found, value) precisely so a JSON null is
        # distinguishable from a missing key.
        assert not ArgumentPredicate(path="x", operator="absent").matches({"x": None})
        assert ArgumentPredicate(path="x", operator="equals", value=None).matches({"x": None})

    def test_booleans_never_satisfy_numeric_comparison(self) -> None:
        # bool subclasses int in Python, so True > 0 is True. A policy author
        # writing `limit > 0` almost certainly did not mean to match `limit: true`.
        assert not ArgumentPredicate(path="n", operator="gt", value=0).matches({"n": True})

    def test_regex_is_validated_at_load_not_on_first_call(self) -> None:
        with pytest.raises(ValidationError):
            ArgumentPredicate(path="q", operator="regex", value="(unclosed")

    def test_regex_requires_a_string_value(self) -> None:
        with pytest.raises(ValidationError):
            ArgumentPredicate(path="q", operator="regex", value=42)

    def test_excessively_deep_path_is_rejected_at_load(self) -> None:
        with pytest.raises(ValidationError, match="maximum depth"):
            ArgumentPredicate(path=".".join(["a"] * 40), operator="absent")

    def test_all_predicates_must_hold(self) -> None:
        rule = Rule(
            id="r",
            effect=Effect.DENY,
            arguments=(
                ArgumentPredicate(path="table", operator="equals", value="users"),
                ArgumentPredicate(path="destructive", operator="equals", value=True),
            ),
        )
        assert rule.matches(call(arguments={"table": "users", "destructive": True}))
        assert not rule.matches(call(arguments={"table": "users", "destructive": False}))

    def test_contains_works_on_strings_and_lists(self) -> None:
        assert ArgumentPredicate(path="q", operator="contains", value="DROP").matches({"q": "DROP TABLE t"})
        assert ArgumentPredicate(path="t", operator="contains", value="x").matches({"t": ["x", "y"]})
        assert not ArgumentPredicate(path="t", operator="contains", value="z").matches({"t": ["x"]})


class TestRealisticPolicy:
    """The shape an operator would actually write: narrow denies, then a
    scoped allow, then nothing -- leaving default deny to catch the rest."""

    @staticmethod
    def build() -> Policy:
        return Policy(
            redact_paths=("credentials.token",),
            rules=(
                Rule(
                    id="no-destructive-sql",
                    effect=Effect.DENY,
                    description="Destructive SQL requires a human, not an agent.",
                    tools=("execute_sql",),
                    arguments=(ArgumentPredicate(path="query", operator="regex", value=r"(?i)\b(drop|truncate)\b"),),
                ),
                Rule(
                    id="prod-writes-need-approval",
                    effect=Effect.REQUIRE_APPROVAL,
                    description="Writes to production are held for review.",
                    servers=("prod-*",),
                    tools=("write_*", "delete_*"),
                ),
                Rule(
                    id="reads-allowed",
                    effect=Effect.ALLOW,
                    description="Read-only tools are unrestricted.",
                    tools=("read_*", "list_*", "execute_sql"),
                ),
            ),
        )

    def test_destructive_sql_denied(self) -> None:
        decision = self.build().evaluate(call(tool="execute_sql", arguments={"query": "DROP TABLE users"}))
        assert decision.effect is Effect.DENY
        assert decision.rule_id == "no-destructive-sql"

    def test_benign_sql_allowed_by_the_later_rule(self) -> None:
        decision = self.build().evaluate(call(tool="execute_sql", arguments={"query": "SELECT 1"}))
        assert decision.effect is Effect.ALLOW
        assert decision.rule_id == "reads-allowed"

    def test_prod_write_is_held(self) -> None:
        decision = self.build().evaluate(call(server="prod-db", tool="write_row"))
        assert decision.effect is Effect.REQUIRE_APPROVAL

    def test_staging_write_falls_through_to_default_deny(self) -> None:
        decision = self.build().evaluate(call(server="staging-db", tool="write_row"))
        assert decision.effect is Effect.DENY
        assert decision.rule_id == IMPLICIT_DEFAULT_RULE_ID

    def test_every_decision_names_a_rule(self) -> None:
        policy = self.build()
        for candidate in (
            call(tool="execute_sql", arguments={"query": "DROP TABLE t"}),
            call(server="prod-db", tool="write_row"),
            call(tool="read_file"),
            call(server="staging", tool="anything"),
        ):
            decision = policy.evaluate(candidate)
            assert decision.rule_id
            assert decision.reason

"""The policy engine: ordered rules, first match wins, default deny.

Three choices shape everything here.

**Firewall semantics, not a scoring model.** Rules are evaluated in written
order and the first match decides. Anyone who has read an iptables or security
group ruleset can read this, and "why was this blocked?" is answered by a line
number rather than by a weighting argument.

**Default deny, stated explicitly.** A policy that matches nothing denies. If
the author did not write that rule, the engine supplies it and says so in the
decision -- `rule_id` is `"<implicit-default-deny>"`, never blank. There is no
configuration that makes the unmatched case allow, because a governance tool
whose failure mode is "permit" is not a governance tool.

**Matching is total and offline.** Every predicate below terminates on any JSON
value, including deeply nested or cyclic-looking structures, and none of them
execute anything from the rule file. A policy is data.
"""

from __future__ import annotations

import fnmatch
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .domain import Decision, Effect, ToolCall

IMPLICIT_DEFAULT_RULE_ID = "<implicit-default-deny>"

_MAX_PATH_DEPTH = 32
"""Argument paths deeper than this are treated as non-matching rather than walked.

A policy file is operator-supplied, but a pathological path costs evaluation
time on every single call, so the walk is bounded rather than trusted.
"""


class ArgumentPredicate(BaseModel):
    """A condition on one argument, addressed by a dotted path.

    `path` walks nested objects and list indices: `"query.limit"`, `"files.0.path"`.
    A path that does not resolve is simply not a match -- absence never satisfies
    a predicate, so a rule that denies on an argument cannot be bypassed by
    omitting it. (Use `absent` when absence is what you mean to match.)
    """

    model_config = ConfigDict(frozen=True)

    path: str = Field(min_length=1)
    operator: Literal["equals", "not_equals", "glob", "regex", "gt", "gte", "lt", "lte", "contains", "absent"]
    value: Any = None

    @field_validator("path")
    @classmethod
    def _path_is_shallow_enough(cls, value: str) -> str:
        if value.count(".") + 1 > _MAX_PATH_DEPTH:
            raise ValueError(f"argument path exceeds maximum depth of {_MAX_PATH_DEPTH}")
        return value

    @model_validator(mode="after")
    def _regex_compiles_at_load(self) -> ArgumentPredicate:
        """Reject an unusable regex when the policy is loaded, not when it first fires.

        A broken pattern discovered on the first call that reaches this rule is
        a denial of service against every request behind it. `re.error` is not a
        `ValueError` subclass, so it is translated here -- otherwise it escapes
        as an unhandled exception instead of a validation failure the operator
        can read.
        """
        if self.operator == "regex":
            if not isinstance(self.value, str):
                raise ValueError("regex predicate requires a string value")
            try:
                re.compile(self.value)
            except re.error as exc:
                raise ValueError(f"invalid regex {self.value!r}: {exc}") from exc
        return self

    def matches(self, arguments: dict[str, Any]) -> bool:
        found, resolved = _resolve(arguments, self.path)
        if self.operator == "absent":
            return not found
        if not found:
            return False
        return _apply(self.operator, resolved, self.value)


class Rule(BaseModel):
    """One ordered rule.

    Unset selectors mean "any". `servers`, `tools`, `tenants` and `scopes` are
    glob lists; `arguments` predicates must *all* hold (AND) for the rule to
    match, which keeps a single rule readable -- express OR by writing two rules.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1)
    effect: Effect
    description: str = Field(default="", description="Shown to the caller when this rule denies.")
    servers: tuple[str, ...] | None = None
    tools: tuple[str, ...] | None = None
    tenants: tuple[str, ...] | None = None
    require_scopes: tuple[str, ...] | None = Field(
        default=None,
        description="Every scope listed must be present on the principal for this rule to match.",
    )
    arguments: tuple[ArgumentPredicate, ...] = ()

    def matches(self, call: ToolCall) -> bool:
        if not _glob_any(self.servers, call.server):
            return False
        if not _glob_any(self.tools, call.tool):
            return False
        if not _glob_any(self.tenants, call.principal.tenant):
            return False
        if self.require_scopes is not None:
            held = set(call.principal.scopes)
            if not set(self.require_scopes).issubset(held):
                return False
        return all(predicate.matches(call.arguments) for predicate in self.arguments)


class Policy(BaseModel):
    """An ordered rule list plus the redaction paths applied before auditing."""

    model_config = ConfigDict(frozen=True)

    version: str = Field(default="1")
    rules: tuple[Rule, ...] = ()
    redact_paths: tuple[str, ...] = Field(
        default=(),
        description="Dotted argument paths whose values never reach the audit log.",
    )

    @field_validator("rules")
    @classmethod
    def _rule_ids_unique(cls, value: tuple[Rule, ...]) -> tuple[Rule, ...]:
        seen: set[str] = set()
        for rule in value:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id!r}")
            seen.add(rule.id)
        return value

    def evaluate(self, call: ToolCall) -> Decision:
        """Return the first matching rule's decision, or the implicit default deny."""
        for index, rule in enumerate(self.rules):
            if rule.matches(call):
                return Decision(
                    effect=rule.effect,
                    rule_id=rule.id,
                    reason=rule.description or f"matched rule {rule.id!r}",
                    matched_index=index,
                )
        return Decision(
            effect=Effect.DENY,
            rule_id=IMPLICIT_DEFAULT_RULE_ID,
            reason=(
                f"no rule matched {call.server}/{call.tool} for tenant {call.principal.tenant!r}; "
                "Turnstile denies by default"
            ),
            matched_index=None,
        )


def _glob_any(patterns: tuple[str, ...] | None, candidate: str) -> bool:
    if patterns is None:
        return True
    return any(fnmatch.fnmatchcase(candidate, pattern) for pattern in patterns)


def _resolve(arguments: dict[str, Any], path: str) -> tuple[bool, Any]:
    """Walk a dotted path. Returns (found, value) so that a legitimate None is
    distinguishable from an absent key -- collapsing those is how "deny when
    `force` is true" silently stops matching `{"force": null}`."""
    current: Any = arguments
    for segment in path.split("."):
        if isinstance(current, dict):
            if segment not in current:
                return False, None
            current = current[segment]
        elif isinstance(current, list):
            try:
                index = int(segment)
            except ValueError:
                return False, None
            if not -len(current) <= index < len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def _apply(operator: str, resolved: Any, expected: Any) -> bool:
    match operator:
        case "equals":
            return bool(resolved == expected)
        case "not_equals":
            return bool(resolved != expected)
        case "glob":
            return isinstance(resolved, str) and isinstance(expected, str) and fnmatch.fnmatchcase(resolved, expected)
        case "regex":
            return isinstance(resolved, str) and re.search(str(expected), resolved) is not None
        case "contains":
            if isinstance(resolved, str) and isinstance(expected, str):
                return expected in resolved
            if isinstance(resolved, list | tuple):
                return expected in resolved
            return False
        case "gt" | "gte" | "lt" | "lte":
            return _compare(operator, resolved, expected)
        case _:  # pragma: no cover - Literal on the field makes this unreachable
            return False


def _compare(operator: str, resolved: Any, expected: Any) -> bool:
    # bool is a subclass of int; comparing True > 0 in a policy is almost
    # certainly a mistake by the policy author, so it does not match.
    if isinstance(resolved, bool) or isinstance(expected, bool):
        return False
    if not isinstance(resolved, int | float) or not isinstance(expected, int | float):
        return False
    match operator:
        case "gt":
            return resolved > expected
        case "gte":
            return resolved >= expected
        case "lt":
            return resolved < expected
        case _:
            return resolved <= expected

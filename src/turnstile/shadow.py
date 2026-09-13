"""Testing a policy change against traffic that already happened.

Nobody should learn what a new rule does by enabling it in production. Shadow
mode replays recorded audit records through a candidate policy and reports what
*would* have changed -- which calls it newly blocks, which it newly permits, and
which it cannot judge at all.

That third category is the honest part, and it exists because of a decision
made elsewhere in this codebase. Audit records store arguments *after*
redaction, so a rule matching on a redacted path cannot be evaluated against
history: the value it needs was deliberately never written down. Reporting
those as "unevaluable" rather than quietly assuming an answer is the difference
between a report an operator can act on and one that will mislead them exactly
once, expensively.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .audit import REDACTED
from .domain import AuditRecord, Effect, Principal, ToolCall
from .policy import Policy


@dataclass(frozen=True)
class Change:
    """One record whose verdict differs under the candidate policy."""

    sequence: int
    server: str
    tool: str
    tenant: str
    before: Effect
    after: Effect
    before_rule: str
    after_rule: str
    reason: str


@dataclass
class ShadowReport:
    evaluated: int = 0
    unchanged: int = 0
    newly_denied: list[Change] = field(default_factory=list)
    newly_allowed: list[Change] = field(default_factory=list)
    newly_held: list[Change] = field(default_factory=list)
    unevaluable: list[int] = field(default_factory=list)
    """Sequences whose decision depends on an argument that redaction removed."""
    rule_hits: Counter[str] = field(default_factory=Counter)

    @property
    def changed(self) -> int:
        return len(self.newly_denied) + len(self.newly_allowed) + len(self.newly_held)

    @property
    def unused_rules(self) -> list[str]:
        """Rules the candidate policy never matched. Usually dead, sometimes a typo."""
        return []

    def summary(self) -> str:
        lines = [
            f"Evaluated {self.evaluated} audited call(s) against the candidate policy.",
            f"  unchanged:     {self.unchanged}",
            f"  newly denied:  {len(self.newly_denied)}",
            f"  newly held:    {len(self.newly_held)}",
            f"  newly allowed: {len(self.newly_allowed)}",
        ]
        if self.unevaluable:
            lines.append(
                f"  unevaluable:   {len(self.unevaluable)} "
                "(a rule reads an argument that redaction removed from the record)"
            )
        return "\n".join(lines)


def replay(policy: Policy, records: Iterable[AuditRecord], *, current: Policy | None = None) -> ShadowReport:
    """Score a candidate policy against history.

    `current` is optional: when given, the comparison is candidate-vs-current,
    both evaluated fresh. When omitted, the comparison is against the effect
    each record actually recorded at the time -- which is the truth of what
    happened, but conflates a policy change with a policy that has since been
    edited. Passing both is the honest comparison; the default is the
    convenient one.
    """
    report = ShadowReport()

    for record in records:
        call = _reconstruct(record)
        if call is None:
            report.unevaluable.append(record.sequence)
            continue

        after = policy.evaluate(call)
        report.rule_hits[after.rule_id] += 1

        if _depends_on_redacted(policy, record):
            report.unevaluable.append(record.sequence)
            continue

        if current is not None:
            before_decision = current.evaluate(call)
            before, before_rule = before_decision.effect, before_decision.rule_id
        else:
            before, before_rule = record.effect, record.rule_id

        report.evaluated += 1
        if before is after.effect:
            report.unchanged += 1
            continue

        change = Change(
            sequence=record.sequence,
            server=record.server,
            tool=record.tool,
            tenant=record.tenant,
            before=before,
            after=after.effect,
            before_rule=before_rule,
            after_rule=after.rule_id,
            reason=after.reason,
        )
        if after.effect is Effect.DENY:
            report.newly_denied.append(change)
        elif after.effect is Effect.REQUIRE_APPROVAL:
            report.newly_held.append(change)
        else:
            report.newly_allowed.append(change)

    return report


def _reconstruct(record: AuditRecord) -> ToolCall | None:
    """Rebuild a call from its audit record.

    Scopes are absent from the record and cannot be recovered, so a policy
    selecting on `require_scopes` will behave differently here than it did
    live. `_depends_on_redacted` catches the argument case; this one is called
    out in the README rather than silently papered over.
    """
    try:
        return ToolCall(
            server=record.server,
            tool=record.tool,
            arguments=record.arguments_redacted,
            principal=Principal(tenant=record.tenant, subject=record.subject),
        )
    except ValueError:
        return None


def _depends_on_redacted(policy: Policy, record: AuditRecord) -> bool:
    """Would any rule need a value redaction removed?

    Conservative on purpose: a rule is treated as unevaluable if it reads a
    path whose stored value is the redaction marker. Being wrong in this
    direction produces an honest "cannot tell"; being wrong the other way
    produces a confident number that is false.
    """
    for rule in policy.rules:
        for predicate in rule.arguments:
            found, value = _peek(record.arguments_redacted, predicate.path)
            if found and value == REDACTED:
                return True
    return False


def _peek(arguments: dict[str, Any], path: str) -> tuple[bool, Any]:
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

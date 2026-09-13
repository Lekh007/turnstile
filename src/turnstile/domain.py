"""The vocabulary of a governed tool call.

Everything in Turnstile is expressed in terms of these types. They are frozen
and free of I/O so that the policy engine can be exercised without a network, a
database, or an MCP server anywhere in sight.

One distinction matters more than any other here. A *decision* is what policy
says should happen; an *outcome* is what actually happened. They are separate
types because they disagree in the interesting cases: a call that policy allowed
can still fail downstream, and a call that policy denied never reaches a server
at all. Collapsing them into one "status" field is how audit logs end up unable
to answer "did we block this, or did it break?"
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Effect(StrEnum):
    """What policy says should happen to a call."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Outcome(StrEnum):
    """What actually happened, recorded after the fact.

    `DENIED` and `FAILED` are deliberately different: the first means the
    upstream server was never contacted, the second means it was and something
    went wrong there. An operator asking "what did we stop last week?" must not
    be handed transport failures in the same bucket.
    """

    COMPLETED = "completed"
    DENIED = "denied"
    AWAITING_APPROVAL = "awaiting_approval"
    FAILED = "failed"
    OVER_BUDGET = "over_budget"


class Principal(BaseModel):
    """Who is making the call.

    MCP is a stateless protocol: nothing may be inferred from the connection, so
    identity is per-request input. On HTTP it comes from the authorization
    framework; on stdio the spec directs implementations to take credentials
    from the environment. Either way it arrives here already resolved -- this
    type never performs authentication, it only carries its result.
    """

    model_config = ConfigDict(frozen=True)

    tenant: str = Field(min_length=1, description="Isolation boundary. Never inferred from a connection.")
    subject: str = Field(min_length=1, description="The acting identity within the tenant.")
    scopes: tuple[str, ...] = ()


class ToolCall(BaseModel):
    """A `tools/call` request, normalised for policy evaluation."""

    model_config = ConfigDict(frozen=True)

    server: str = Field(min_length=1, description="Which upstream MCP server the call is bound for.")
    tool: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    principal: Principal
    request_id: str | int | None = None
    """The JSON-RPC id, kept so a decision can be correlated to the wire message."""


class Decision(BaseModel):
    """The result of evaluating policy against one call.

    `rule_id` and `reason` are not optional niceties. A governance decision
    nobody can explain is indistinguishable from a bug, so every path that
    produces a Decision -- including the implicit default -- must name the rule
    that produced it.
    """

    model_config = ConfigDict(frozen=True)

    effect: Effect
    rule_id: str = Field(min_length=1, description="Which rule decided. Never empty, including for defaults.")
    reason: str = Field(min_length=1, description="Human-readable, safe to show a caller.")
    matched_index: int | None = Field(
        default=None,
        description="Position in the ordered rule list, or None when the implicit default decided.",
    )

    @property
    def is_allowed(self) -> bool:
        return self.effect is Effect.ALLOW


class AuditRecord(BaseModel):
    """One immutable entry in the hash-chained audit log.

    `arguments_redacted` holds arguments *after* redaction, never before. An
    audit log that faithfully records an API key someone passed to a tool has
    turned itself into the most attractive target in the system.
    """

    model_config = ConfigDict(frozen=True)

    sequence: int = Field(ge=0)
    recorded_at: datetime
    tenant: str
    subject: str
    server: str
    tool: str
    arguments_redacted: dict[str, Any]
    effect: Effect
    rule_id: str
    reason: str
    outcome: Outcome
    result_digest: str | None = Field(
        default=None,
        description="SHA-256 of the upstream result, so a result can be proven unaltered without storing it.",
    )
    duration_ms: float | None = Field(default=None, ge=0)
    previous_digest: str = Field(description="Digest of the preceding record; the genesis record uses GENESIS_DIGEST.")
    digest: str = Field(description="This record's digest, covering its own content and previous_digest.")


def utcnow() -> datetime:
    """Timezone-aware now, in one place so tests can substitute it."""
    return datetime.now(UTC)

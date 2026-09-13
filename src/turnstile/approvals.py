"""Holding a call until a human says yes.

A `REQUIRE_APPROVAL` decision is worthless unless approving is possible and
*narrow*. Four rules make it narrow, and each of them closes a way an approval
could be turned into more authority than the approver intended:

**An approval is bound to the exact call.** It covers one server, one tool, and
one specific set of arguments, matched by digest. Approving "delete
/tmp/scratch" must not authorise "delete /etc/passwd" -- an approval that
covers a *tool* rather than a *call* is a permanent grant wearing a
human's signature.

**An approval is single use.** It is consumed the moment the call proceeds.
Otherwise one approved deletion authorises unlimited deletions.

**An approval expires.** A request approved on Monday should not still be
executable on Friday; by then nobody remembers the context that made it fine.

**An approver may not approve their own request.** Separation of duties, and
the reason it matters here specifically: the requester is frequently an agent
acting *as* the requesting human, so without this rule "ask a human" collapses
into the agent asking itself.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .domain import ToolCall, utcnow

DEFAULT_TTL_SECONDS = 900


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalError(Exception):
    """An approval could not be granted or used, with a reason safe to show."""


def call_digest(call: ToolCall) -> str:
    """Identify the exact call an approval covers.

    Covers server, tool and arguments -- not the principal, so that an approval
    granted for a request survives the requester retrying it, and not the
    request id, which changes on every retry. Canonical JSON so the digest does
    not depend on key ordering.
    """
    canonical = json.dumps(
        {"server": call.server, "tool": call.tool, "arguments": call.arguments},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    digest: str = Field(description="Digest of the exact call this covers.")
    tenant: str
    requested_by: str
    server: str
    tool: str
    arguments_redacted: dict[str, Any]
    requested_at: datetime
    expires_at: datetime
    state: ApprovalState = ApprovalState.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None
    reason: str = ""

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at


class ApprovalStore:
    """In-memory pending approvals.

    Not persisted, deliberately. A durable approval queue needs a defined
    lifetime, a reset policy and somewhere trustworthy to live; choosing one
    silently would mean approvals behaving differently after a restart than
    before it. The audit log is the durable record of what was asked and what
    was decided -- this is the live queue.
    """

    def __init__(self, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._requests: dict[str, ApprovalRequest] = {}

    def request(self, call: ToolCall, *, arguments_redacted: dict[str, Any]) -> ApprovalRequest:
        """Record that a call is waiting for a human.

        The id is `secrets`-generated rather than sequential: a guessable
        approval id would let anyone who can reach the approve command consume
        a hold they never saw.
        """
        now = utcnow()
        record = ApprovalRequest(
            id=secrets.token_urlsafe(12),
            digest=call_digest(call),
            tenant=call.principal.tenant,
            requested_by=call.principal.subject,
            server=call.server,
            tool=call.tool,
            arguments_redacted=arguments_redacted,
            requested_at=now,
            expires_at=now + self._ttl,
        )
        self._requests[record.id] = record
        return record

    def get(self, approval_id: str) -> ApprovalRequest | None:
        return self._requests.get(approval_id)

    def pending(self, *, tenant: str | None = None) -> list[ApprovalRequest]:
        now = utcnow()
        return [
            record
            for record in self._requests.values()
            if record.state is ApprovalState.PENDING
            and not record.is_expired(now=now)
            and (tenant is None or record.tenant == tenant)
        ]

    def decide(self, approval_id: str, *, approver: str, approve: bool, reason: str = "") -> ApprovalRequest:
        record = self._requests.get(approval_id)
        if record is None:
            raise ApprovalError(f"no such approval: {approval_id!r}")
        if record.state is not ApprovalState.PENDING:
            raise ApprovalError(f"approval {approval_id!r} is already {record.state.value}")
        if record.is_expired():
            expired = record.model_copy(update={"state": ApprovalState.EXPIRED})
            self._requests[approval_id] = expired
            raise ApprovalError(f"approval {approval_id!r} expired at {record.expires_at.isoformat()}")
        if approver == record.requested_by:
            raise ApprovalError(
                f"{approver!r} requested this call and may not also approve it; "
                "an agent acting as the requester must not be able to approve itself"
            )

        decided = record.model_copy(
            update={
                "state": ApprovalState.APPROVED if approve else ApprovalState.REJECTED,
                "decided_by": approver,
                "decided_at": utcnow(),
                "reason": reason,
            }
        )
        self._requests[approval_id] = decided
        return decided

    def consume(self, call: ToolCall) -> ApprovalRequest | None:
        """Find and spend an approval covering exactly this call.

        Returns None when nothing matches, which the gateway treats as "still
        needs a human" -- the safe direction. Consumption is why an approval
        authorises one execution rather than a standing permission.
        """
        digest = call_digest(call)
        now = utcnow()
        for approval_id, record in self._requests.items():
            if record.state is not ApprovalState.APPROVED:
                continue
            if record.digest != digest or record.tenant != call.principal.tenant:
                continue
            if record.is_expired(now=now):
                self._requests[approval_id] = record.model_copy(update={"state": ApprovalState.EXPIRED})
                continue
            self._requests[approval_id] = record.model_copy(update={"state": ApprovalState.CONSUMED})
            return record
        return None

    def purge_expired(self) -> int:
        now = utcnow()
        purged = 0
        for approval_id, record in list(self._requests.items()):
            if record.state in {ApprovalState.PENDING, ApprovalState.APPROVED} and record.is_expired(now=now):
                self._requests[approval_id] = record.model_copy(update={"state": ApprovalState.EXPIRED})
                purged += 1
        return purged

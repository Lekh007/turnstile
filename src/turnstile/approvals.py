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

The queue is durable, and the three decisions behind that are now explicit:

**Lifetime** is the unchanged TTL. Durability does not extend it; an approval
that would have expired before the restart still expires.

**Reset policy: there is none.** Rows survive a restart and expiry is an
explicit state transition, never a silent wipe. That is the point of
persistence: the gateway can die while a call is held, a human can decide in
its absence, and the agent's next retry finds the decision waiting.

**Where it lives:** the same SQLite file as the audit chain, in a separate
table. Approval writes never touch the chain. State changes are compare-and-set
(`UPDATE ... WHERE state = <expected>`), so a gateway and a console deciding
over one file cannot double-decide a request or consume one approval twice --
the loser of the race sees `state` moved on and reports it, rather than both
succeeding.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .domain import ToolCall, utcnow

DEFAULT_TTL_SECONDS = 900

IN_MEMORY = ":memory:"
"""Same magic path as the audit log: a queue that is not kept."""


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalError(Exception):
    """An approval could not be granted or used, with a reason safe to show."""


class ApprovalStoreUnavailable(Exception):
    """The approval store could not be opened.

    Raised at startup rather than turned into a degraded mode: a configuration
    that asks for durable approvals and cannot have them should stop the
    operator's day loudly, not quietly hold calls in a queue that vanishes.
    """

    def __init__(self, path: Path | str, reason: BaseException) -> None:
        super().__init__(
            f"cannot open the approval store at {str(path)!r}: {reason}. "
            f"Point 'approvals_path' at a writable location, or use {IN_MEMORY!r} "
            "for a queue that is not kept."
        )
        self.path = str(path)


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


_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id                 TEXT PRIMARY KEY,
    digest             TEXT NOT NULL,
    tenant             TEXT NOT NULL,
    requested_by       TEXT NOT NULL,
    server             TEXT NOT NULL,
    tool               TEXT NOT NULL,
    arguments_redacted TEXT NOT NULL,
    requested_at       TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    state              TEXT NOT NULL,
    decided_by         TEXT,
    decided_at         TEXT,
    reason             TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS approvals_state_idx ON approvals (state, tenant);
CREATE INDEX IF NOT EXISTS approvals_digest_idx ON approvals (digest, tenant, state);
"""


def _record_from_row(row: sqlite3.Row) -> ApprovalRequest:
    return ApprovalRequest(
        id=str(row["id"]),
        digest=str(row["digest"]),
        tenant=str(row["tenant"]),
        requested_by=str(row["requested_by"]),
        server=str(row["server"]),
        tool=str(row["tool"]),
        arguments_redacted=json.loads(str(row["arguments_redacted"])),
        requested_at=datetime.fromisoformat(str(row["requested_at"])),
        expires_at=datetime.fromisoformat(str(row["expires_at"])),
        state=ApprovalState(str(row["state"])),
        decided_by=row["decided_by"] if row["decided_by"] is None else str(row["decided_by"]),
        decided_at=row["decided_at"] if row["decided_at"] is None else datetime.fromisoformat(str(row["decided_at"])),
        reason=str(row["reason"]),
    )


class ApprovalStore:
    """SQLite-backed approval queue. Embedded on purpose, like the audit log:
    one file the gateway writes and a future console reads, not a database
    cluster to stand up before an agent may ask for permission."""

    def __init__(self, path: Path | str = IN_MEMORY, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        if str(path) != IN_MEMORY:
            try:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ApprovalStoreUnavailable(path, exc) from exc
        try:
            self._connection = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            if str(path) != IN_MEMORY:
                # Two processes share this file (the gateway holds, a console
                # decides). WAL keeps a reader from blocking the writer, and a
                # busy timeout turns the rare collision into a wait instead of
                # an "database is locked" error under no real load at all.
                self._connection.execute("PRAGMA journal_mode=WAL")
                self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise ApprovalStoreUnavailable(path, exc) from exc

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> ApprovalStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

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
        self._connection.execute(
            "INSERT INTO approvals (id, digest, tenant, requested_by, server, tool, arguments_redacted,"
            " requested_at, expires_at, state, decided_by, decided_at, reason)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, '')",
            (
                record.id,
                record.digest,
                record.tenant,
                record.requested_by,
                record.server,
                record.tool,
                json.dumps(record.arguments_redacted, default=str),
                record.requested_at.isoformat(),
                record.expires_at.isoformat(),
                record.state.value,
            ),
        )
        return record

    def get(self, approval_id: str) -> ApprovalRequest | None:
        row = self._connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return None if row is None else _record_from_row(row)

    def pending(self, *, tenant: str | None = None) -> list[ApprovalRequest]:
        """Live holds: PENDING and not yet past their expiry.

        Expiry is applied here rather than only by a sweep, so a caller never
        sees a hold it could usefully act on that has in fact lapsed. Marking
        the row EXPIRED is deliberate bookkeeping, not garbage collection: an
        auditor can see that a hold lapsed unapproved.
        """
        now = utcnow()
        if tenant is None:
            rows = self._connection.execute(
                "SELECT * FROM approvals WHERE state = ? ORDER BY requested_at", (ApprovalState.PENDING.value,)
            ).fetchall()
        else:
            rows = self._connection.execute(
                "SELECT * FROM approvals WHERE state = ? AND tenant = ? ORDER BY requested_at",
                (ApprovalState.PENDING.value, tenant),
            ).fetchall()
        live: list[ApprovalRequest] = []
        for row in rows:
            record = _record_from_row(row)
            if record.is_expired(now=now):
                self._expire(record)
                continue
            live.append(record)
        return live

    def decide(self, approval_id: str, *, approver: str, approve: bool, reason: str = "") -> ApprovalRequest:
        row = self._connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            raise ApprovalError(f"no such approval: {approval_id!r}")
        record = _record_from_row(row)
        if record.state is not ApprovalState.PENDING:
            raise ApprovalError(f"approval {approval_id!r} is already {record.state.value}")
        if record.is_expired():
            self._expire(record)
            raise ApprovalError(f"approval {approval_id!r} expired at {record.expires_at.isoformat()}")
        if approver == record.requested_by:
            raise ApprovalError(
                f"{approver!r} requested this call and may not also approve it; "
                "an agent acting as the requester must not be able to approve itself"
            )

        decided_at = utcnow()
        state = ApprovalState.APPROVED if approve else ApprovalState.REJECTED
        # Compare-and-set on the state: if another process decided this same
        # request while we checked it, the UPDATE matches nothing and the loser
        # reports the race instead of both decisions landing.
        cursor = self._connection.execute(
            "UPDATE approvals SET state = ?, decided_by = ?, decided_at = ?, reason = ?"
            " WHERE id = ? AND state = ?",
            (state.value, approver, decided_at.isoformat(), reason, approval_id, ApprovalState.PENDING.value),
        )
        if cursor.rowcount != 1:
            raise ApprovalError(f"approval {approval_id!r} is already decided")
        return record.model_copy(
            update={
                "state": state,
                "decided_by": approver,
                "decided_at": decided_at,
                "reason": reason,
            }
        )

    def consume(self, call: ToolCall) -> ApprovalRequest | None:
        """Find and spend an approval covering exactly this call.

        Returns None when nothing matches, which the gateway treats as "still
        needs a human" -- the safe direction. Consumption is why an approval
        authorises one execution rather than a standing permission.
        """
        digest = call_digest(call)
        now = utcnow()
        rows = self._connection.execute(
            "SELECT * FROM approvals WHERE digest = ? AND tenant = ? AND state = ? ORDER BY requested_at",
            (digest, call.principal.tenant, ApprovalState.APPROVED.value),
        ).fetchall()
        for row in rows:
            record = _record_from_row(row)
            if record.is_expired(now=now):
                self._expire(record)
                continue
            spent = self._connection.execute(
                "UPDATE approvals SET state = ? WHERE id = ? AND state = ?",
                (ApprovalState.CONSUMED.value, record.id, ApprovalState.APPROVED.value),
            )
            if spent.rowcount == 1:
                return record.model_copy(update={"state": ApprovalState.CONSUMED})
            # Another process consumed this one between the SELECT and the
            # UPDATE; try the next approved row for the same call.
            continue
        return None

    def purge_expired(self) -> int:
        cursor = self._connection.execute(
            "UPDATE approvals SET state = ?"
            " WHERE state IN (?, ?) AND expires_at <= ?",
            (
                ApprovalState.EXPIRED.value,
                ApprovalState.PENDING.value,
                ApprovalState.APPROVED.value,
                utcnow().isoformat(),
            ),
        )
        return cursor.rowcount

    def _expire(self, record: ApprovalRequest) -> None:
        self._connection.execute(
            "UPDATE approvals SET state = ? WHERE id = ? AND state = ?",
            (ApprovalState.EXPIRED.value, record.id, record.state.value),
        )

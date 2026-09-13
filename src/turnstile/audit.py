"""Append-only, hash-chained audit log.

Each record carries the digest of the record before it, and its own digest
covers both its content and that link. Altering or removing any record breaks
every digest after it, so tampering is detectable by re-walking the chain --
`verify()` does exactly that and names the first record that fails.

This is tamper-*evident*, not tamper-proof. Anyone who can rewrite the whole
store can recompute the whole chain. Making it tamper-proof means putting the
head digest somewhere the writer cannot reach, which is a deployment decision
rather than a code one; `head_digest()` exists so that is possible.

Arguments are redacted *before* they arrive here. See `redact`.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from .domain import AuditRecord, Decision, Outcome, ToolCall, utcnow

GENESIS_DIGEST = "0" * 64
"""The previous_digest of the first record. A literal, so an empty chain still verifies."""

REDACTED = "[redacted]"


class ChainBroken(Exception):
    """Raised when the audit chain does not verify. Carries the failing sequence."""

    def __init__(self, sequence: int, detail: str) -> None:
        super().__init__(f"audit chain broken at sequence {sequence}: {detail}")
        self.sequence = sequence
        self.detail = detail


def redact(arguments: dict[str, Any], paths: Sequence[str]) -> dict[str, Any]:
    """Return a copy with every listed dotted path replaced by `[redacted]`.

    The input is never mutated: the caller still needs the real arguments to
    forward upstream, and a redaction function that quietly destroys them would
    break the call it was meant to make safe.

    A path that does not resolve is not an error. Policies outlive the tools
    they describe, and a stale redaction path should not fail a call -- it just
    redacts nothing.
    """
    redacted = json.loads(json.dumps(arguments, default=str))
    for path in paths:
        _redact_one(redacted, path.split("."))
    return dict(redacted)


def _redact_one(node: Any, segments: Sequence[str]) -> None:
    head, rest = segments[0], segments[1:]
    if isinstance(node, dict):
        if head not in node:
            return
        if not rest:
            node[head] = REDACTED
            return
        _redact_one(node[head], rest)
        return
    if isinstance(node, list):
        try:
            index = int(head)
        except ValueError:
            return
        if not -len(node) <= index < len(node):
            return
        if not rest:
            node[index] = REDACTED
            return
        _redact_one(node[index], rest)


def compute_digest(payload: dict[str, Any], previous_digest: str) -> str:
    """SHA-256 over canonical JSON of the record content plus the previous link.

    `sort_keys` and the explicit separators matter: the digest has to be
    reproducible by an auditor re-deriving it later, possibly in another
    language, so the serialisation cannot depend on dict insertion order or on
    a JSON encoder's default spacing.
    """
    canonical = json.dumps(
        {"content": payload, "previous_digest": previous_digest},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    sequence           INTEGER PRIMARY KEY,
    recorded_at        TEXT    NOT NULL,
    tenant             TEXT    NOT NULL,
    subject            TEXT    NOT NULL,
    server             TEXT    NOT NULL,
    tool               TEXT    NOT NULL,
    arguments_redacted TEXT    NOT NULL,
    effect             TEXT    NOT NULL,
    rule_id            TEXT    NOT NULL,
    reason             TEXT    NOT NULL,
    outcome            TEXT    NOT NULL,
    result_digest      TEXT,
    duration_ms        REAL,
    previous_digest    TEXT    NOT NULL,
    digest             TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_tenant_idx ON audit (tenant, sequence);
"""


class AuditLog:
    """SQLite-backed chain. Embedded on purpose -- a governance gateway that
    needs its own database cluster before it can log a refusal is not one anyone
    will deploy in front of a laptop agent."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self._connection = sqlite3.connect(str(path), isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(_SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def head_digest(self) -> str:
        row = self._connection.execute("SELECT digest FROM audit ORDER BY sequence DESC LIMIT 1").fetchone()
        return GENESIS_DIGEST if row is None else str(row["digest"])

    def append(
        self,
        *,
        call: ToolCall,
        decision: Decision,
        outcome: Outcome,
        redact_paths: Sequence[str] = (),
        result_digest: str | None = None,
        duration_ms: float | None = None,
    ) -> AuditRecord:
        row = self._connection.execute("SELECT COALESCE(MAX(sequence) + 1, 0) AS next FROM audit").fetchone()
        sequence = int(row["next"])
        previous = self.head_digest()
        recorded_at = utcnow()
        arguments_redacted = redact(call.arguments, redact_paths)

        content: dict[str, Any] = {
            "sequence": sequence,
            "recorded_at": recorded_at.isoformat(),
            "tenant": call.principal.tenant,
            "subject": call.principal.subject,
            "server": call.server,
            "tool": call.tool,
            "arguments_redacted": arguments_redacted,
            "effect": decision.effect.value,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "outcome": outcome.value,
            "result_digest": result_digest,
            "duration_ms": duration_ms,
        }
        digest = compute_digest(content, previous)

        self._connection.execute(
            "INSERT INTO audit (sequence, recorded_at, tenant, subject, server, tool, arguments_redacted,"
            " effect, rule_id, reason, outcome, result_digest, duration_ms, previous_digest, digest)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                sequence,
                content["recorded_at"],
                content["tenant"],
                content["subject"],
                content["server"],
                content["tool"],
                json.dumps(arguments_redacted, sort_keys=True),
                content["effect"],
                content["rule_id"],
                content["reason"],
                content["outcome"],
                result_digest,
                duration_ms,
                previous,
                digest,
            ),
        )
        return AuditRecord(
            sequence=sequence,
            recorded_at=recorded_at,
            tenant=call.principal.tenant,
            subject=call.principal.subject,
            server=call.server,
            tool=call.tool,
            arguments_redacted=arguments_redacted,
            effect=decision.effect,
            rule_id=decision.rule_id,
            reason=decision.reason,
            outcome=outcome,
            result_digest=result_digest,
            duration_ms=duration_ms,
            previous_digest=previous,
            digest=digest,
        )

    def records(self, *, tenant: str | None = None) -> Iterator[AuditRecord]:
        """Yield records oldest first.

        `tenant` is the isolation boundary. It is applied in SQL rather than by
        filtering in Python so that a caller cannot accidentally receive another
        tenant's rows and discard them after the fact.
        """
        if tenant is None:
            cursor = self._connection.execute("SELECT * FROM audit ORDER BY sequence")
        else:
            cursor = self._connection.execute("SELECT * FROM audit WHERE tenant = ? ORDER BY sequence", (tenant,))
        for row in cursor:
            yield _row_to_record(row)

    def verify(self) -> int:
        """Re-walk the chain, recomputing every digest. Returns the record count.

        Raises `ChainBroken` naming the first sequence that fails, so an
        operator learns *where* the log was altered, not merely that it was.
        """
        expected_previous = GENESIS_DIGEST
        count = 0
        for expected_sequence, row in enumerate(self._connection.execute("SELECT * FROM audit ORDER BY sequence")):
            record = _row_to_record(row)
            if record.sequence != expected_sequence:
                raise ChainBroken(record.sequence, f"expected sequence {expected_sequence}; a record was removed")
            if record.previous_digest != expected_previous:
                raise ChainBroken(record.sequence, "previous_digest does not match the preceding record")
            content = {
                "sequence": record.sequence,
                "recorded_at": record.recorded_at.isoformat(),
                "tenant": record.tenant,
                "subject": record.subject,
                "server": record.server,
                "tool": record.tool,
                "arguments_redacted": record.arguments_redacted,
                "effect": record.effect.value,
                "rule_id": record.rule_id,
                "reason": record.reason,
                "outcome": record.outcome.value,
                "result_digest": record.result_digest,
                "duration_ms": record.duration_ms,
            }
            if compute_digest(content, record.previous_digest) != record.digest:
                raise ChainBroken(record.sequence, "content does not match its digest")
            expected_previous = record.digest
            count += 1
        return count


def _row_to_record(row: sqlite3.Row) -> AuditRecord:
    from datetime import datetime

    return AuditRecord(
        sequence=int(row["sequence"]),
        recorded_at=datetime.fromisoformat(str(row["recorded_at"])),
        tenant=str(row["tenant"]),
        subject=str(row["subject"]),
        server=str(row["server"]),
        tool=str(row["tool"]),
        arguments_redacted=dict(json.loads(str(row["arguments_redacted"]))),
        effect=row["effect"],
        rule_id=str(row["rule_id"]),
        reason=str(row["reason"]),
        outcome=row["outcome"],
        result_digest=None if row["result_digest"] is None else str(row["result_digest"]),
        duration_ms=None if row["duration_ms"] is None else float(row["duration_ms"]),
        previous_digest=str(row["previous_digest"]),
        digest=str(row["digest"]),
    )

"""The gateway: one place every tool call passes through.

The order of checks is the design. Policy is evaluated *before* budget, and both
before the upstream server is contacted:

1. **Policy** decides whether this call is permitted at all. A denied call must
   never consume budget -- otherwise a caller could exhaust a tenant's ceiling
   by hammering calls they were never allowed to make.
2. **Budget** decides whether a permitted call can be afforded right now.
3. **Forward**, and only then, to the upstream server.
4. **Audit**, always -- on every path, including the ones that never reached a
   server. A governance log with holes in it where refusals should be is worse
   than no log, because it looks complete.

Step 4 is the one worth stating twice. `handle` records an audit entry before it
returns on every branch, including when the upstream transport raises.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from .audit import AuditLog
from .budget import Budget, BudgetLedger
from .domain import Decision, Effect, Outcome, Principal, ToolCall
from .mcp import MalformedRequest, denial_response, error_response, parse_tool_call, text_result
from .policy import Policy


class UpstreamTransport(Protocol):
    """How a permitted call reaches its real MCP server.

    A Protocol rather than a class so the gateway can be tested with no network
    and no subprocess, and so stdio and Streamable HTTP transports are
    interchangeable without the gateway knowing which it has.
    """

    def call(self, server: str, message: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class GatewayResult:
    """What the gateway produced, and why.

    `response` is the JSON-RPC message to hand back to the caller. `decision`
    and `outcome` are the governance facts -- kept alongside rather than parsed
    back out of the response, because reconstructing intent from a wire message
    is exactly the mistake that makes audit logs untrustworthy.
    """

    response: dict[str, Any]
    decision: Decision | None
    outcome: Outcome | None
    audited: bool


class Gateway:
    def __init__(
        self,
        *,
        policy: Policy,
        transport: UpstreamTransport,
        audit_log: AuditLog,
        budget: Budget | None = None,
        ledger: BudgetLedger | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._policy = policy
        self._transport = transport
        self._audit = audit_log
        self._budget = budget
        self._ledger = ledger if ledger is not None else BudgetLedger()
        self._clock = clock

    def handle(self, server: str, message: dict[str, Any], principal: Principal) -> GatewayResult:
        request_id = message.get("id")

        try:
            tool, arguments = parse_tool_call(message)
        except MalformedRequest as exc:
            # Nothing is audited here on purpose: without a valid tool name and
            # arguments there is no call to describe, and writing a
            # half-understood message into the governance log would put
            # unvalidated caller input into the record an auditor trusts.
            return GatewayResult(
                response=error_response(request_id, code=exc.code, message=exc.message),
                decision=None,
                outcome=None,
                audited=False,
            )

        call = ToolCall(
            server=server,
            tool=tool,
            arguments=arguments,
            principal=principal,
            request_id=request_id,
        )
        decision = self._policy.evaluate(call)

        if decision.effect is Effect.DENY:
            self._record(call, decision, Outcome.DENIED)
            return GatewayResult(
                response=denial_response(request_id, reason=decision.reason, rule_id=decision.rule_id),
                decision=decision,
                outcome=Outcome.DENIED,
                audited=True,
            )

        if decision.effect is Effect.REQUIRE_APPROVAL:
            # Held, not forwarded. The call has been recorded as awaiting a
            # human; nothing reaches the upstream server until one arrives.
            self._record(call, decision, Outcome.AWAITING_APPROVAL)
            return GatewayResult(
                response={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": text_result(
                        f"Held for approval by Turnstile policy [{decision.rule_id}]: {decision.reason}",
                        is_error=True,
                    ),
                },
                decision=decision,
                outcome=Outcome.AWAITING_APPROVAL,
                audited=True,
            )

        if self._budget is not None:
            verdict = self._budget.check(self._ledger, call)
            if not verdict.within:
                self._record(call, decision, Outcome.OVER_BUDGET)
                return GatewayResult(
                    response=denial_response(request_id, reason=verdict.reason, rule_id=f"budget:{verdict.limit_name}"),
                    decision=decision,
                    outcome=Outcome.OVER_BUDGET,
                    audited=True,
                )

        started = self._clock()
        try:
            upstream = self._transport.call(server, message)
        except Exception as exc:  # noqa: BLE001 - any transport failure is still a governed event
            duration_ms = (self._clock() - started) * 1000
            self._record(call, decision, Outcome.FAILED, duration_ms=duration_ms)
            return GatewayResult(
                response=error_response(request_id, code=-32603, message=f"upstream transport failed: {exc}"),
                decision=decision,
                outcome=Outcome.FAILED,
                audited=True,
            )

        duration_ms = (self._clock() - started) * 1000
        self._ledger.record(call)
        self._record(
            call,
            decision,
            Outcome.COMPLETED,
            result_digest=digest_result(upstream),
            duration_ms=duration_ms,
        )
        return GatewayResult(response=upstream, decision=decision, outcome=Outcome.COMPLETED, audited=True)

    def _record(
        self,
        call: ToolCall,
        decision: Decision,
        outcome: Outcome,
        *,
        result_digest: str | None = None,
        duration_ms: float | None = None,
    ) -> None:
        self._audit.append(
            call=call,
            decision=decision,
            outcome=outcome,
            redact_paths=self._policy.redact_paths,
            result_digest=result_digest,
            duration_ms=duration_ms,
        )


def digest_result(result: dict[str, Any]) -> str:
    """SHA-256 of an upstream result.

    The gateway stores the digest, not the payload. Tool results routinely carry
    the very data a tenant would least like duplicated into a second store, and
    a digest is enough to prove later that a result was not altered.
    """
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

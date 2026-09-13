"""Per-tenant ceilings, enforced as a hard stop.

"Escalating costs" is one of the three reasons agentic projects get cancelled,
and the usual reason cost runs away is that the control was a dashboard rather
than a gate. A budget that emails someone at 80% has not stopped anything.

So `check` is consulted *before* a call is forwarded and its answer is binding.
Two properties follow from that and are worth naming:

* **Denied and held calls never consume budget.** They are refused before this
  module is consulted at all (see `gateway.handle`), so a caller cannot exhaust
  a tenant's ceiling with calls they were never permitted to make.
* **Budget is counted on completion, not on attempt.** `record` runs after the
  upstream call returns. A call that failed in transport cost the tenant
  nothing, and charging for it would let a flapping upstream server burn a
  ceiling that protects against something else entirely.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .domain import ToolCall


@dataclass(frozen=True)
class BudgetVerdict:
    within: bool
    limit_name: str
    reason: str


class BudgetLedger:
    """In-memory tallies, keyed by tenant.

    Deliberately not persisted. A ledger surviving restarts is a different
    product decision with real consequences -- it needs a defined window, a
    reset policy, and somewhere durable to live -- and quietly picking one here
    would mean a ceiling that behaves differently after a deploy than before it.
    `AuditLog` is the durable record; this is the live counter.
    """

    def __init__(self) -> None:
        self._calls: dict[str, int] = defaultdict(int)
        self._per_tool: dict[tuple[str, str], int] = defaultdict(int)

    def record(self, call: ToolCall) -> None:
        self._calls[call.principal.tenant] += 1
        self._per_tool[(call.principal.tenant, call.tool)] += 1

    def calls_for(self, tenant: str) -> int:
        return self._calls[tenant]

    def calls_for_tool(self, tenant: str, tool: str) -> int:
        return self._per_tool[(tenant, tool)]


@dataclass(frozen=True)
class Budget:
    """Ceilings applied to a tenant.

    `max_calls` is the overall ceiling; `max_calls_per_tool` narrows specific
    tools. Both are inclusive ceilings -- the call that would take the tenant
    *past* the limit is the one refused, so a `max_calls` of 5 permits exactly
    five calls.
    """

    max_calls: int | None = None
    max_calls_per_tool: dict[str, int] = field(default_factory=dict)

    def check(self, ledger: BudgetLedger, call: ToolCall) -> BudgetVerdict:
        tenant = call.principal.tenant

        per_tool_limit = self.max_calls_per_tool.get(call.tool)
        if per_tool_limit is not None:
            used = ledger.calls_for_tool(tenant, call.tool)
            if used >= per_tool_limit:
                return BudgetVerdict(
                    within=False,
                    limit_name=f"max_calls_per_tool[{call.tool}]",
                    reason=(
                        f"tenant {tenant!r} has used {used} of {per_tool_limit} permitted calls to {call.tool!r}"
                    ),
                )

        if self.max_calls is not None:
            used = ledger.calls_for(tenant)
            if used >= self.max_calls:
                return BudgetVerdict(
                    within=False,
                    limit_name="max_calls",
                    reason=f"tenant {tenant!r} has used {used} of {self.max_calls} permitted calls",
                )

        return BudgetVerdict(within=True, limit_name="", reason="within budget")

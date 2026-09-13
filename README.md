# Turnstile

**A policy, audit and budget gateway for MCP tool calls — where the default answer is no.**

Every `tools/call` an agent makes passes through one controlled point. Turnstile decides whether
it is permitted, whether the tenant can afford it, and records what happened in a hash-chained
log — before the upstream server is ever contacted.

It is a proxy, not a framework. Point an MCP client at Turnstile instead of at the real servers
and nothing else changes.

## Why this exists

Gartner expects **more than 40% of agentic AI projects to be cancelled by the end of 2027**, and
the reasons given are escalating costs, unclear business value, and inadequate risk controls. Two
of those three are controls that don't exist yet:

- *"What is this agent actually allowed to do?"* — usually answered by a system prompt, which is a
  request, not a control.
- *"What did it do last Tuesday?"* — usually answered by logs the agent's own process wrote.
- *"What did that cost, and what stops it?"* — usually answered by a dashboard nobody watches.

Turnstile answers all three mechanically. Policy is a data file, not a prompt. The audit log is
tamper-evident and written by the gateway, not the agent. The budget is a gate, not an alert.

## The four decisions that define it

**Default deny, stated out loud.** A call matching no rule is denied, and the decision says so —
`rule_id` is `"<implicit-default-deny>"`, never blank. There is no configuration that makes the
unmatched case allow. A governance tool whose failure mode is *permit* is not a governance tool.

**Firewall semantics.** Rules are evaluated in written order and the first match decides. "Why was
this blocked?" is answered by a rule id and a line number, not by a scoring argument.

**A refusal is a tool result, not a protocol error.** The MCP specification reserves error codes
`-32020`–`-32099` for itself, and says clients *should* hand tool execution errors to the model so
it can self-correct. So Turnstile refuses with `isError: true` and the rule id in the text. The
agent learns the door is closed and routes around it, instead of retrying a transport-shaped
failure in a loop.

**Arguments are redacted before they are audited.** An audit log that faithfully records the API
key someone passed to a tool has turned itself into the most attractive target in the system.

## What a policy looks like

```python
Policy(
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
        Rule(id="reads-allowed", effect=Effect.ALLOW, tools=("read_*", "list_*", "execute_sql")),
    ),
)
```

`SELECT 1` reaches the database. `DROP TABLE users` does not, and the agent is told which rule
stopped it. A write to `staging-db` matches nothing and is denied by default — which is the point:
adding a server does not silently grant access to it.

## The audit log

Append-only and hash-chained: each record carries the digest of the one before it, and its own
digest covers both its content and that link. Altering or deleting any record breaks every digest
after it, and `verify()` names the first sequence that fails — so an operator learns *where* the
log was altered, not merely that it was.

```python
log.verify()          # -> record count, or raises ChainBroken(sequence=..., detail=...)
log.head_digest()     # publish this somewhere the writer cannot reach
```

This is tamper-*evident*, not tamper-proof: anyone who can rewrite the whole store can recompute
the whole chain. Making it tamper-proof means anchoring `head_digest()` outside the writer's
reach, which is a deployment decision rather than a code one.

Results are stored as a SHA-256 digest, never as the payload. Tool results routinely carry exactly
the data a tenant would least like copied into a second store, and a digest is enough to prove
later that a result was not altered.

## What it refuses to do

- **Denied and held calls never reach the upstream server.** Proven by a transport that records
  every call it receives, and asserted to be empty.
- **Denied and held calls never consume budget.** Otherwise a caller could exhaust a tenant's
  ceiling with calls they were never permitted to make.
- **Failed calls never consume budget.** A flapping upstream must not burn a ceiling that exists
  to control cost.
- **A malformed request is never audited.** Without a validated tool name there is no call to
  describe, and writing half-understood caller input into the record an auditor trusts is worse
  than writing nothing.
- **Every other path is audited**, including refusals and upstream failures. A governance log with
  holes where refusals belong is worse than no log, because it looks complete.

## Protocol conformance

Built against the **2026-07-28** MCP revision, which matters in three specific ways:

- MCP is now explicitly a **stateless** protocol — nothing may be inferred from a connection. That
  suits a proxy: there is no handshake to remember. It also means every request must carry
  `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in
  `_meta`, and Turnstile rejects a request missing either with `-32602`, as the spec requires.
- Results carry `resultType`. An absent one means a server on an earlier revision and is read as
  `"complete"` — defaulting the other way would make every older server look like it was asking
  for more input.
- Filtering `tools/list` by policy is explicitly permitted: the tool set "MAY vary by the
  authorization presented on the request". Filtering means a model is never shown a tool it would
  only be refused for using. It is not a security boundary on its own, so `tools/call` is
  evaluated against policy regardless of what `tools/list` returned.

## Run the gates

```bash
uv sync
uv run ruff check src tests
uv run mypy src          # strict
uv run pytest
```

## Status and scope

An early vertical slice: the policy engine, the audit chain, budgets, and the gateway decision path
are implemented and tested. **Not yet built**: the stdio and Streamable HTTP transports that carry
it in front of a real client, the approval queue that resolves a `REQUIRE_APPROVAL` hold, shadow
mode for testing a policy against recorded traffic, and session replay.

A `REQUIRE_APPROVAL` decision currently holds the call and records it as awaiting a human; there is
no mechanism yet to deliver that approval. The natural fit is MCP's own `InputRequiredResult` and
elicitation — the gateway asking the operator for approval through the protocol it is already
speaking — which is the next thing to build.

Not a production system, and not a security boundary against an attacker who controls the host.

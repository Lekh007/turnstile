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

## Use it

Turnstile runs as an MCP server over stdio. Point a client at it instead of at your real servers,
and list those servers in its config:

```json
{
  "principal": { "tenant": "acme", "subject": "you", "scopes": ["read"] },
  "servers": {
    "files": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/demo"] }
  },
  "policy": {
    "rules": [
      { "id": "deletes-need-a-human", "effect": "require_approval", "tools": ["delete_*"] },
      { "id": "reads-are-free", "effect": "allow", "tools": ["read_*", "list_*"] }
    ]
  }
}
```

```bash
python -m turnstile --config turnstile.json
```

A fuller example, with redaction, budgets and a scope-gated write rule, is in
[`examples/turnstile.json`](examples/turnstile.json).

Tools are exposed as `<server>.<tool>` — the specification asks aggregating proxies to
disambiguate, since two servers may each expose a `search`. Routing splits on the *first* dot, so
`admin.tools.list` (itself a legal tool name) survives being prefixed.

Here is a real run against two rules, one allowing reads and one denying deletes:

```text
discover  -> ['2026-07-28']
tools     -> ['files.read_file']
call      -> ALLOWED: files:read_file:{"path": "/tmp/notes.txt"}
call      -> BLOCKED: Refused by Turnstile policy [deletes-denied]: Agents do not delete files.
```

`files.delete_file` is absent from the tool list because policy denies it outright — the model is
never shown a tool it would only be refused for using. A tool that is *conditionally* denied still
appears, because argument predicates cannot be judged without arguments, and hiding it would deny a
capability that is legal for some inputs.

## The rule that breaks proxies

**stdout carries MCP messages and nothing else.** The specification states it as a MUST NOT, and
the failure is disproportionate: one stray banner, warning or traceback makes the client fail to
parse the stream, and the error it reports points at JSON rather than at whatever printed. Every
diagnostic here goes to stderr, which the spec explicitly permits and tells clients not to read as
failure. A test drives the proxy through a scripted session — including a garbage input line — and
asserts every single stdout line parses as a valid MCP message.

## Run the gates

```bash
uv sync
uv run ruff check src tests
uv run mypy src          # strict
uv run pytest
```

The transport tests spawn a real MCP server subprocess ([`tests/fixtures/fake_mcp_server.py`](tests/fixtures/fake_mcp_server.py))
rather than mocking it, because framing, interleaved notifications, stderr tolerance and
shutdown-on-EOF are invisible to a mock and are exactly what breaks the first time a proxy meets a
real server.

## Status and scope

Implemented and tested: the policy engine, the hash-chained audit log, budgets, the gateway
decision path, and the **stdio transport** with multi-server aggregation, prefix routing, protocol
version negotiation and notification passthrough.

**Not yet built**: the Streamable HTTP transport; the approval queue that resolves a
`REQUIRE_APPROVAL` hold; identity-provider integration so roles come from OIDC/SAML groups rather
than a config file; shadow mode for testing a policy against recorded traffic; and session replay.

A `REQUIRE_APPROVAL` decision currently holds the call and records it as awaiting a human, but
there is no mechanism yet to deliver that approval. The natural fit is MCP's own
`InputRequiredResult` and elicitation — the gateway asking the operator through the protocol it is
already speaking.

`principal` is configured rather than authenticated. On stdio that is defensible — the transport
has no authorization framework, and the specification directs stdio implementations to take
credentials from the environment — but it means this is not yet a multi-user system. Deriving the
principal from a real identity provider changes that field's source, not its meaning.

Not a production system, and not a security boundary against an attacker who controls the host.

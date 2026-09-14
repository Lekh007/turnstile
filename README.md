# Turnstile

[![CI](https://github.com/Lekh007/turnstile/actions/workflows/ci.yml/badge.svg)](https://github.com/Lekh007/turnstile/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Checked with mypy --strict](https://img.shields.io/badge/mypy-strict-blue.svg)](https://mypy-lang.org/)

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

## Who the agent is acting for

An agent must never hold more authority than the person it acts for — and usually holds less.

Every company already has an identity provider that knows who is in which group, so Turnstile
authenticates nobody itself. It verifies a signed OIDC token, maps the groups inside it onto the
scopes its rules select on, and hands the result to the policy engine as a principal.

```json
"identity": {
  "settings": { "algorithms": ["RS256"], "issuer": "https://login.example.com/acme", "audience": "turnstile" },
  "roles": {
    "base_scopes": ["read"],
    "groups": {
      "support-leads": ["tickets"],
      "finance":       ["ledger"],
      "directors":     ["ledger", "approve", "write"]
    }
  }
}
```

Three real people, three real signed tokens, **one unchanged policy**:

```text
--- as priya (groups: support-leads) ---
  tools visible : ['fin.read_file']
  delete_file   : BLOCKED
--- as sam (groups: finance) ---
  tools visible : ['fin.read_file']
  delete_file   : BLOCKED
--- as dana (groups: directors) ---
  tools visible : ['fin.read_file', 'fin.delete_file']
  delete_file   : ALLOWED
```

Two properties are enforced in code rather than left to configuration:

- **The signature is always verified.** There is no flag that disables it, and `alg: none` cannot
  even be configured — it is signature stripping, not an algorithm. Expiry, audience and issuer are
  named explicitly rather than left to library defaults, so a future default change cannot quietly
  switch one off.
- **An unmapped group grants nothing.** Default deny applied to identity: creating a group at the
  IdP is never accidentally a grant inside Turnstile.

`turnstile whoami` exists because the commonest identity failure is not a rejected token but an
accepted one that yields fewer scopes than expected — which looks exactly like a policy bug until
you can see the mapping:

```json
{ "principal": { "subject": "sam", "scopes": ["ledger", "read"] },
  "groups_presented": ["finance", "mystery-team"],
  "groups_unmapped":  ["mystery-team"] }
```

Credentials come from the environment (`TURNSTILE_JWT_KEY`, `TURNSTILE_ID_TOKEN`), never from the
config file — and on stdio that is what the specification points at, since the transport carries no
authorization of its own. If identity is configured and the token is missing or invalid, the
gateway **refuses to start** rather than falling back to the config-file principal. Falling back
would mean granting access on the strength of a file instead of an identity provider, which is the
exact failure this layer exists to prevent.

## Holding a call for a human

A `require_approval` decision parks the call and returns an approval id. Four rules keep an
approval narrow, and each closes a way it could become more authority than the approver intended:

- **Bound to the exact call** — one server, one tool, one specific set of arguments, matched by
  digest. Approving `delete /tmp/scratch` must never authorise `delete /etc/passwd`.
- **Single use** — consumed the moment the call proceeds, so one approved deletion does not
  authorise unlimited deletions.
- **Expires** — a request approved on Monday should not still execute on Friday.
- **The requester cannot approve themselves** — and this one matters here specifically, because the
  requester is usually an agent acting *as* a human. Without it, "ask a human" collapses into the
  agent asking itself.

The audit log then records `approval:<id>` and the approver's name as the reason the call was
permitted — not a policy rule, because a rule is not what permitted it.

## Testing a policy change before shipping it

Nobody should learn what a new rule does by enabling it in production.

```bash
turnstile shadow --config turnstile.json --candidate stricter-policy.json
```

```text
Evaluated 431 audited call(s) against the candidate policy.
  unchanged:     403
  newly denied:  26
  newly held:    2
  newly allowed: 0
  unevaluable:   3 (a rule reads an argument that redaction removed from the record)
```

That last line is the honest part. Audit records store arguments *after* redaction, so a rule
matching on a redacted path cannot be scored against history — the value it needs was deliberately
never written down. Reporting those as unevaluable rather than assuming an answer is the difference
between a report an operator can act on and one that misleads them exactly once, expensively.
Scopes are likewise absent from audit records, so a candidate rule selecting on `require_scopes`
will not score faithfully; that limit is stated here rather than papered over.

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
decision path, the **stdio transport** with multi-server aggregation and prefix routing,
**OIDC identity with group-to-scope mapping**, the **approval flow**, and **shadow mode**.

**Not yet built**, and honestly out of scope for a portfolio slice rather than forgotten:

- **The Streamable HTTP transport.** stdio is what Claude Desktop and Claude Code use, so it is
  what makes this demonstrable; HTTP is what a shared multi-user deployment would need, along with
  the authorization framework that comes with it.
- **Approval delivery through the protocol.** Approvals are granted out of band today. The natural
  fit is MCP's own `InputRequiredResult` and elicitation — the gateway asking the operator through
  the protocol it is already speaking — rather than a separate channel.
- **A durable approval queue.** Deliberately in-memory: a persisted queue needs a defined lifetime
  and reset policy, and choosing one silently would mean approvals behaving differently after a
  restart than before it.
- **Anchoring the audit head digest** somewhere the writer cannot reach, which is what would make
  the log tamper-*proof* rather than tamper-evident.

Not a production system, and not a security boundary against an attacker who controls the host: a
policy file, a verification key and an audit database all live somewhere that host can reach.

Not a production system, and not a security boundary against an attacker who controls the host.

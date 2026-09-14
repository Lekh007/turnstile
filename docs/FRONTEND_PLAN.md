# Turnstile Console — implementation plan

A local-first web console for the people Turnstile governs on behalf of:
the **approver** who must say yes to a held call, the **operator** who
writes policy, and the **auditor** who has to believe the log.

This document is the build order. Each phase ends with something that runs,
something that is tested, and CI still green.

---

## 0. The three facts that determine the design

Read these before anything else. Everything below follows from them.

### 0.1 `REQUIRE_APPROVAL` is currently an elaborate deny

`ApprovalStore` holds pending approvals **in a Python dict, in the gateway
process** (`src/turnstile/approvals.py`). The gateway runs as a stdio
subprocess spawned by the MCP client. So today there is no way — none — for a
human to see a held call, let alone approve one.

The docstring is honest about it:

> Not persisted, deliberately. A durable approval queue needs a defined
> lifetime, a reset policy and somewhere trustworthy to live; choosing one
> silently would mean approvals behaving differently after a restart than
> before it.

Those three choices are now ours to make, explicitly. That is Phase 1, and it
is the single highest-value piece of work in this plan. **The console is not a
skin over a working feature; it is what makes the feature exist.**

### 0.2 The approval flow is already asynchronous, which makes this easy

From `Gateway.handle`:

1. Policy returns `REQUIRE_APPROVAL`.
2. Gateway looks for an existing approval covering *this exact call*
   (`consume`). None found.
3. Gateway records `AWAITING_APPROVAL`, creates a pending request, and
   **returns immediately** with `Approval id: <id> (expires ...)`.
4. Later the agent retries. `consume` now finds the granted approval, spends
   it, and the call proceeds — audited with `rule_id="approval:<id>"`.

Nothing blocks. No websockets, no server push, no long-poll required. The
console writes a decision; the next retry picks it up. A humble HTML form is
sufficient.

### 0.3 The audit log is a hash chain, so the console must never write to it

Each record's digest covers its content **and** the previous record's digest.
Two processes appending concurrently will interleave `previous_digest` reads
and produce a chain that fails `verify()`.

**Rule, non-negotiable: the web process opens the audit database read-only and
the gateway remains the only writer.** Not by convention — enforced, by
opening with a `file:...?mode=ro` URI so a stray `INSERT` raises instead of
corrupting. A console that breaks the chain it exists to display would
discredit the entire project.

Approval decisions do not need to touch the chain: `decided_by`, `decided_at`
and `reason` live on the approval row, and the audit record is written by the
gateway when the approval is consumed.

---

## 1. Architecture

```
┌──────────────────────┐
│  MCP client          │   (Claude Desktop, Cursor, …)
│  spawns ▼ stdio      │
├──────────────────────┤
│  turnstile serve     │  writes: audit chain, approval requests
│  (gateway process)   │  reads:  approval decisions
└──────────┬───────────┘
           │
      ┌────▼─────────────────────────┐
      │  turnstile.sqlite3           │   one file, WAL mode
      │   audit      (gateway RW)    │
      │   approvals  (both RW)       │
      └────▲─────────────────────────┘
           │
┌──────────┴───────────┐
│  turnstile console   │  reads:  audit (READ-ONLY), approvals
│  (uvicorn, 127.0.0.1)│  writes: approval decisions only
└──────────────────────┘
```

### Why shared SQLite and not the alternatives

| Option | Verdict |
|---|---|
| **Shared SQLite file** | **Chosen.** No daemon, survives restarts, works offline, matches the project's existing "embedded on purpose" stance. |
| HTTP server on a thread inside the gateway | Rejected. The gateway lives and dies with the MCP client, and several clients would spawn several conflicting servers. |
| A separate coordination daemon | Rejected. More processes, more failure modes, more to explain — for no capability the file does not already provide. |

### SQLite settings this requires

Two processes on one file needs three pragmas, set once at open:

- `journal_mode=WAL` — readers do not block the writer. Persists in the file.
- `busy_timeout=5000` — a concurrent writer **waits** instead of raising
  `database is locked`. Without this you will see flaky failures under no real
  load at all.
- `check_same_thread=False` — uvicorn serves on a worker thread.

---

## 2. Stack

**FastAPI + Jinja2 + HTMX, server-rendered, vendored assets, no build step.**

- **No `node_modules`.** Your disk is nearly full; a build chain costs
  hundreds of megabytes and buys nothing here.
- **Testable in the existing suite.** `TestClient` + `pytest`, same CI job,
  same `mypy --strict`. A React app would need a second toolchain and a second
  CI job to reach the same confidence.
- **You already know it.** Quarterline uses Jinja templates with vendored
  `htmx.min.js` — same shape, and portfolio consistency is a small free win.
- **HTMX gives a live-feeling inbox** with `hx-get` + `hx-trigger="every 5s"`
  on one element. That is the entire real-time requirement.

**Honest tradeoff:** if the goal were to demonstrate front-end engineering
depth, React + Vite would signal more. For an FDE / AI-engineer role the
differentiator is the governance substrate, and a SPA adds a build chain, a
second lockfile and a CORS surface for little signal. Revisit only if a
specific job description demands React.

### Dependencies — keep the core install at two packages

```toml
[project.optional-dependencies]
web = ["fastapi>=0.115", "uvicorn[standard]>=0.32", "jinja2>=3.1", "python-multipart>=0.0.9"]
```

`pip install turnstile` stays a two-dependency install (`pydantic`, `pyjwt`).
`pip install turnstile[web]` adds the console. That separation is worth
stating in an interview: the governance core does not drag a web framework
into a security-sensitive dependency tree.

---

## 3. Security — a console over a policy gateway is a privilege surface

Anyone who reaches `/approvals` can authorise tool calls. Treat it that way.

| # | Control | Why |
|---|---|---|
| S1 | **Bind `127.0.0.1` by default.** `--host` exists but warns loudly. | A governance console on `0.0.0.0` is worse than no console. |
| S2 | **The approver is derived from a verified token, never from a form field.** | If the user can type any name, separation of duties (rule 4) is decorative. Reuse `TokenPrincipalResolver`. |
| S3 | **`approve` scope required to decide.** | `RoleMapping` already maps `directors → ledger, approve, write`. Wire it; do not invent a second permission model. |
| S4 | **CSRF token on every POST.** | A page in another tab can POST to `127.0.0.1`. Localhost is not a trust boundary. |
| S5 | **Render `arguments_redacted` only.** | The console must be unable to leak what redaction removed — it reads the stored record, which never held the secret. |
| S6 | **Audit DB opened read-only.** | §0.3. Enforced by the connection URI. |
| S7 | **No token, key or secret ever rendered into HTML.** | Includes error pages and debug output. |

### Separation of duties in a single-user local setup

Rule 4 says the requester may not approve their own call. Locally you are both.
Do not weaken the rule — demonstrate it:

- Gateway config: `principal.subject = "priya"` (the agent acts as Priya).
- Console config: a **different** principal, `subject = "dana"`, with the
  `approve` scope.

Now approving works, and pointing the console at Priya's identity correctly
refuses with *"priya requested this call and may not also approve it"*. That
refusal is a better demo moment than the approval.

---

## 4. Screens

| Route | Audience | Backed by |
|---|---|---|
| `/` Dashboard | everyone | counts by outcome, pending badge, chain status |
| `/approvals` **Inbox** | **approver** | `ApprovalStore.pending()` / `decide()` |
| `/activity` Decision feed | operator | `AuditLog.records()` + new filters |
| `/activity/{sequence}` Record detail | auditor | one `AuditRecord` + chain position |
| `/chain` Integrity | auditor | `AuditLog.verify()`, `head_digest()` |
| `/shadow` Policy testing | policy author | `shadow.replay()` → `ShadowReport` |
| `/whoami` Identity | operator | `TokenPrincipalResolver.explain()` |

Everything except the approvals inbox is **rendering logic that already
exists**. `/shadow` in particular is close to free: `ShadowReport` already
carries `newly_denied`, `newly_allowed`, `newly_held`, `unused_rules`,
`unevaluable` and `rule_hits`, and `summary()` already prose-formats it.

### `/approvals` — the screen that matters

Each pending hold shows:

- **Who** — `requested_by`, `tenant`
- **What** — `server` / `tool`, arguments pretty-printed (redacted)
- **Why held** — the rule id and its reason, taken from the audit record
- **When it expires** — a live countdown; an expired hold cannot be approved
- **Approve** / **Reject**, each requiring a short reason

Design notes:
- Show the **digest prefix**, and state that the approval covers *this exact
  call*. The whole value proposition is on that line.
- After deciding, the card moves to a "Decided" list with who and when —
  the approver must be able to see what they just did.
- Empty state is not "no data": it is *"Nothing is waiting on you."*

---

## 5. Build order

### Phase 0 — Scaffolding (½ session)
- `web` optional dependency group; `src/turnstile/web/` package.
- `turnstile --config … console --port 8787` subcommand.
- One route (`/healthz`), one test, `mypy --strict` clean, CI green.
- **Done when:** the server starts, the test passes, nothing else changed.

### Phase 1 — Persist approvals ⚠️ *the blocker* (1–2 sessions)
Make the three choices the docstring deferred:
- **Where:** the same SQLite file as the audit log, table `approvals`.
- **Lifetime:** rows persist; `expires_at` already governs usability. Add
  `purge_expired()` on a timer *and* on read, so a restart cannot resurrect a
  stale hold.
- **Reset:** none. Approvals are governance history; `state` records the
  outcome. Deletion is an explicit admin action, not a restart side effect.

Work:
- `SqliteApprovalStore` with the same interface as the current in-memory one.
  Keep the in-memory implementation for tests — make both satisfy a Protocol.
- WAL + `busy_timeout` at open.
- Wire `TurnstileConfig` so the gateway and console resolve the same path.

**Tests that matter:**
- Every existing approvals test passes against the SQLite implementation
  (parametrise the suite over both).
- **Two-connection test:** write a decision on connection A, prove connection B
  sees it. This is the test that proves the architecture.
- Restart test: a granted approval survives reopening; an expired one is not
  resurrected.

**Done when:** a decision written by one process is consumed by another.

### Phase 2 — Audit query surface (½–1 session)
`records()` is oldest-first, unbounded, tenant-only. A console cannot page
100k rows to show 50. Add:
- `records(..., newest_first=True, limit=N, offset=M)`
- filters: `outcome`, `effect`, `tool`, `subject`, `rule_id`, time range
- `record(sequence)` for the detail page
- `counts_by_outcome(tenant)` for the dashboard
- `open_readonly(path)` — the enforced read-only connection (§0.3)

**Tests:** filters compose; `limit`/`offset` page without gaps or repeats; a
write attempt through the read-only connection **raises**.

### Phase 3 — Approvals inbox (1–2 sessions)
The money screen. Base layout, inbox, decide endpoints, CSRF, scope gate,
HTMX 5-second refresh.

**Tests:** approve → state APPROVED; reject → REJECTED; self-approval refused
with the real message; expired hold cannot be approved; missing CSRF token
rejected; a principal without `approve` gets 403.

**Done when:** you can run the gateway, trigger a held call from a real MCP
client, approve it in the browser, and watch the retry succeed.

### Phase 4 — Activity feed + record detail (1 session)
Newest-first table, filter bar, detail page showing digest, `previous_digest`
and chain position.

**Test:** the whole surface runs against a populated DB and `verify()` still
passes afterwards — proof the console never wrote to the chain.

### Phase 5 — Chain integrity + whoami (½ session)
`/chain` runs `verify()` and reports intact + head digest, or names the first
failing sequence. `/whoami` renders `explain()`, including
`groups_unmapped` — the commonest identity failure is an accepted token with
fewer scopes than expected, which looks exactly like a policy bug.

### Phase 6 — Shadow mode (1 session)
Paste or upload a candidate policy; render the diff: newly denied / held /
allowed, unused rules, and **unevaluable records with the reason**. Do not
hide the unevaluable count — it is the honest part of the feature.

### Phase 7 — Polish and demo (1 session)
Dark mode, empty states, README screenshots, and a scripted three-user demo:
Priya blocked, Sam allowed, Dana approves a hold. Record it.

---

## 6. Proposed layout

```
src/turnstile/web/
├── __init__.py
├── app.py              # create_app(config) -> FastAPI
├── deps.py             # read-only audit conn, approval store, principal, CSRF
├── routes/
│   ├── dashboard.py  approvals.py  activity.py  chain.py  shadow.py
├── templates/
│   ├── base.html  dashboard.html  approvals.html  activity.html
│   ├── record.html  chain.html  shadow.html
│   └── partials/     # HTMX fragments: approval_card, activity_rows, …
└── static/
    ├── app.css
    └── vendor/htmx.min.js      # vendored, not CDN
tests/web/
├── conftest.py  test_approvals_ui.py  test_activity_ui.py
├── test_security.py            # CSRF, scope gate, read-only enforcement
└── test_chain_safety.py        # verify() still passes after UI traffic
```

**Keep logic out of templates.** Jinja is not type-checked; anything a template
computes is invisible to `mypy --strict`. Build a view-model in Python, pass it
in, let the template only render.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Console write corrupts the hash chain | Read-only connection, enforced; `test_chain_safety` |
| `database is locked` flakes | WAL + `busy_timeout=5000` |
| Approver identity spoofable | Token-derived only; never a form field (S2) |
| Self-approval quietly permitted | Existing rule 4 + an explicit test |
| Scope creep into a full SPA | Phases 0–3 first; ship the inbox before anything else |
| Approvals schema churn | Settle the table in Phase 1 before any template exists |

---

## 8. Definition of done

- [ ] A held call can be approved by a human in a browser and the retry succeeds
- [ ] A different human cannot approve their own request
- [ ] The console cannot write to the audit chain, and a test proves it
- [ ] `verify()` passes after a full session of console use
- [ ] `ruff`, `mypy --strict`, and the full suite pass; CI green
- [ ] `pip install turnstile` still installs two dependencies
- [ ] README shows the inbox, and the three-user demo is recorded

---

## 9. What to build first, tomorrow

Phase 1. Not the UI.

Until approvals are persisted, every screen is a mock. Once they are, the
inbox is a form over a table — and the feature the README already advertises
becomes real for the first time.

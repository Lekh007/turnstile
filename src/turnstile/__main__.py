"""The Turnstile command line.

`serve` is the one an MCP client launches; the rest are for the human who owns
the policy.

    turnstile serve   --config turnstile.json    # the gateway itself
    turnstile whoami  --config turnstile.json    # what identity resolves to, and why
    turnstile shadow  --config turnstile.json --candidate new-policy.json
    turnstile verify  --config turnstile.json    # re-walk the audit chain

Every diagnostic goes to stderr. `serve` may not print to stdout for any reason
other than an MCP message -- see `proxy` for why that rule is absolute. The
other subcommands never run the protocol, so they print to stdout normally.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .approvals import ApprovalStore
from .audit import IN_MEMORY, AuditLog, AuditUnavailable, ChainBroken
from .budget import BudgetLedger
from .config import TurnstileConfig
from .identity import IdentityError, TokenPrincipalResolver
from .policy import Policy
from .proxy import Proxy
from .registry import ToolRegistry
from .shadow import replay
from .upstream import StdioUpstream, log


def _load(path: Path) -> TurnstileConfig:
    try:
        return TurnstileConfig.load(path)
    except Exception as exc:  # noqa: BLE001 - any load failure is fatal and must be legible
        # A gateway that starts with a policy it could not parse would be worse
        # than one that refuses to start: it would look like it was governing.
        log(f"[turnstile] could not load config {path}: {exc}")
        raise SystemExit(2) from exc


def serve(config: TurnstileConfig) -> int:
    try:
        principal = config.resolve_principal()
    except (IdentityError, ValueError) as exc:
        # Fatal, never a fallback. Dropping back to a config-file principal
        # when a token is missing would mean granting access on the strength of
        # a file instead of an identity provider.
        log(f"[turnstile] refusing to start: {exc}")
        return 3

    upstreams: dict[str, StdioUpstream] = {}
    for name, server in config.servers.items():
        upstream = StdioUpstream(name, server.command, list(server.args), env=server.resolved_env())
        upstream.start()
        upstreams[name] = upstream
        log(f"[turnstile] started upstream {name!r}: {server.command}")

    audit_log = AuditLog(config.audit_path)
    approvals_path = config.approvals_path if config.approvals_path is not None else config.audit_path
    proxy = Proxy(
        registry=ToolRegistry(dict(upstreams)),
        policy=config.policy,
        audit_log=audit_log,
        principal=principal,
        budget=config.budget.to_budget() if config.budget else None,
        ledger=BudgetLedger(),
        approvals=ApprovalStore(approvals_path, ttl_seconds=config.approval_ttl_seconds),
    )

    log(
        f"[turnstile] acting for {principal.subject!r} in tenant {principal.tenant!r} "
        f"with scopes {list(principal.scopes)}"
    )
    log(
        f"[turnstile] governing {len(upstreams)} server(s) with {len(config.policy.rules)} rule(s); "
        "anything unmatched is denied"
    )

    try:
        proxy.serve()
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        log("[turnstile] interrupted")
    finally:
        for name, upstream in upstreams.items():
            upstream.stop()
            log(f"[turnstile] stopped upstream {name!r}")
        audit_log.close()
    return 0


def whoami(config: TurnstileConfig) -> int:
    """Show what identity resolves to, and which groups the mapping ignored.

    The commonest identity failure is not a rejected token but an accepted one
    that yields fewer scopes than expected -- which looks exactly like a policy
    bug until someone can see the mapping.
    """
    if config.identity is None:
        principal = config.principal
        print(json.dumps({"source": "config", "principal": principal.model_dump()}, indent=2, default=str))
        return 0

    try:
        resolver = config.identity.build_resolver()
        assert isinstance(resolver, TokenPrincipalResolver)
        report = resolver.explain(config.identity.credential())
    except (IdentityError, ValueError) as exc:
        print(json.dumps({"source": "identity", "error": str(exc)}, indent=2))
        return 1

    print(json.dumps({"source": "identity", **report}, indent=2, default=str))
    if report["groups_unmapped"]:
        log(
            f"[turnstile] note: {len(report['groups_unmapped'])} group(s) in the token have no "
            "entry in the role mapping and therefore granted nothing"
        )
    return 0


def shadow(config: TurnstileConfig, candidate_path: Path) -> int:
    """Replay the audit log through a candidate policy and report the delta."""
    if config.audit_path == IN_MEMORY:
        log("[turnstile] audit_path is ':memory:', so there is no history to replay against")
        return 1

    try:
        candidate = Policy.model_validate(json.loads(candidate_path.read_text(encoding="utf-8")))
    except Exception as exc:  # noqa: BLE001
        log(f"[turnstile] could not load candidate policy {candidate_path}: {exc}")
        return 2

    audit_log = AuditLog(config.audit_path)
    try:
        report = replay(candidate, audit_log.records(), current=config.policy)
    finally:
        audit_log.close()

    print(report.summary())
    for heading, changes in (
        ("Newly denied", report.newly_denied),
        ("Newly held for approval", report.newly_held),
        ("Newly allowed", report.newly_allowed),
    ):
        if not changes:
            continue
        print(f"\n{heading}:")
        for change in changes:
            print(f"  #{change.sequence} {change.server}/{change.tool} "
                  f"[{change.before_rule} -> {change.after_rule}] {change.reason}")
    return 0


def verify(config: TurnstileConfig) -> int:
    """Re-walk the audit chain and report where, if anywhere, it breaks."""
    audit_log = AuditLog(config.audit_path)
    try:
        count = audit_log.verify()
    except ChainBroken as exc:
        print(f"AUDIT CHAIN BROKEN at sequence {exc.sequence}: {exc.detail}")
        return 1
    finally:
        audit_log.close()
    print(f"Audit chain intact: {count} record(s) verified.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="turnstile", description="A policy gateway for MCP tool calls.")
    parser.add_argument("--config", required=True, type=Path, help="Path to a Turnstile JSON config file.")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("serve", help="Run the gateway over stdio (the default).")
    subparsers.add_parser("whoami", help="Show the resolved principal and role mapping.")
    subparsers.add_parser("verify", help="Re-walk the audit chain.")
    shadow_parser = subparsers.add_parser("shadow", help="Replay the audit log through a candidate policy.")
    shadow_parser.add_argument("--candidate", required=True, type=Path, help="A JSON policy document.")

    arguments = parser.parse_args(argv)
    config = _load(arguments.config)

    try:
        match arguments.command:
            case "whoami":
                return whoami(config)
            case "verify":
                return verify(config)
            case "shadow":
                return shadow(config, arguments.candidate)
            case _:
                # Default to serve, so a client config that names no subcommand
                # still launches the gateway.
                return serve(config)
    except AuditUnavailable as exc:
        # A misconfigured audit_path is an operator mistake with a one-line fix,
        # and a traceback would point at sqlite rather than at the setting.
        print(f"turnstile: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

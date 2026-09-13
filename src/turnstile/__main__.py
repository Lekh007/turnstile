"""`python -m turnstile --config turnstile.json`

The process an MCP client launches. It starts every configured upstream, serves
the client on stdin/stdout until end of file, and shuts the upstreams down on
the way out.

Every diagnostic goes to stderr. Not one line of this module may print to
stdout for any reason other than an MCP message -- see `proxy` for why that
rule is absolute.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .audit import AuditLog
from .budget import BudgetLedger
from .config import TurnstileConfig
from .proxy import Proxy
from .registry import ToolRegistry
from .upstream import StdioUpstream, log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="turnstile", description="A policy gateway for MCP tool calls.")
    parser.add_argument("--config", required=True, type=Path, help="Path to a Turnstile JSON config file.")
    arguments = parser.parse_args(argv)

    try:
        config = TurnstileConfig.load(arguments.config)
    except Exception as exc:  # noqa: BLE001 - any load failure is fatal and must be legible
        # A gateway that starts with a policy it could not parse would be worse
        # than one that refuses to start: it would look like it was governing.
        log(f"[turnstile] could not load config {arguments.config}: {exc}")
        return 2

    upstreams: dict[str, StdioUpstream] = {}
    for name, server in config.servers.items():
        upstream = StdioUpstream(name, server.command, list(server.args), env=server.resolved_env())
        upstream.start()
        upstreams[name] = upstream
        log(f"[turnstile] started upstream {name!r}: {server.command}")

    audit_log = AuditLog(config.audit_path)
    proxy = Proxy(
        registry=ToolRegistry(dict(upstreams)),
        policy=config.policy,
        audit_log=audit_log,
        principal=config.principal,
        budget=config.budget.to_budget() if config.budget else None,
        ledger=BudgetLedger(),
    )

    rule_count = len(config.policy.rules)
    log(
        f"[turnstile] governing {len(upstreams)} server(s) with {rule_count} rule(s); "
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


if __name__ == "__main__":
    sys.exit(main())

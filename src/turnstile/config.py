"""Loading a gateway from a config file.

The policy lives in a file an operator writes and a reviewer can read in a pull
request. That is the point of the whole project: the rules governing what an
agent may do must be somewhere a human owns, not somewhere the agent can see,
influence, or be persuaded to reinterpret.

The file is data. Nothing in it is executed, and it cannot name code to run --
only servers to launch, which the operator chose, and rules to apply.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .budget import Budget
from .domain import Principal
from .identity import (
    PrincipalResolver,
    RoleMapping,
    StaticPrincipalResolver,
    TokenPrincipalResolver,
    TokenSettings,
)
from .policy import Policy


class ServerConfig(BaseModel):
    """How to launch one upstream MCP server."""

    model_config = ConfigDict(frozen=True)

    command: str = Field(min_length=1)
    args: tuple[str, ...] = ()
    env: dict[str, str] = Field(
        default_factory=dict,
        description="Extra environment for this server, merged over the gateway's own.",
    )
    inherit_env: bool = Field(
        default=True,
        description=(
            "Pass the gateway's environment through. On stdio the specification directs "
            "servers to take credentials from the environment, so turning this off means "
            "the server gets only what `env` names -- tighter, and a common reason a "
            "previously working server suddenly cannot authenticate."
        ),
    )

    def resolved_env(self) -> dict[str, str]:
        base = dict(os.environ) if self.inherit_env else {}
        base.update(self.env)
        return base


class BudgetConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_calls: int | None = None
    max_calls_per_tool: dict[str, int] = Field(default_factory=dict)

    def to_budget(self) -> Budget:
        return Budget(max_calls=self.max_calls, max_calls_per_tool=dict(self.max_calls_per_tool))


class IdentityConfig(BaseModel):
    """Where the principal comes from, when it is not simply configured.

    `key_env` and `token_env` name environment variables rather than holding
    values: a verification key or a token committed to a config file is a
    credential in version control. On stdio this is also what the specification
    points at -- implementations there "should retrieve credentials from the
    environment" rather than from the protocol.
    """

    model_config = ConfigDict(frozen=True)

    settings: TokenSettings
    roles: RoleMapping = RoleMapping()
    key_env: str = Field(default="TURNSTILE_JWT_KEY", min_length=1)
    token_env: str = Field(default="TURNSTILE_ID_TOKEN", min_length=1)

    def build_resolver(self) -> TokenPrincipalResolver:
        key = os.environ.get(self.key_env)
        if not key:
            raise ValueError(
                f"identity is configured but {self.key_env} is unset; "
                "Turnstile will not verify tokens against an empty key"
            )
        return TokenPrincipalResolver(key=key, settings=self.settings, mapping=self.roles)

    def credential(self) -> str | None:
        return os.environ.get(self.token_env)


class TurnstileConfig(BaseModel):
    """The whole gateway, declared in one file."""

    model_config = ConfigDict(frozen=True)

    principal: Principal = Principal(tenant="default", subject="local")
    """Who the gateway acts for, when no identity provider is configured.

    Honest for a single-user stdio deployment: the client launches the gateway
    as one person, and the transport carries no authorization. Set `identity`
    instead to derive the principal from a verified token, which is what makes
    scope-gated rules mean anything.
    """

    servers: dict[str, ServerConfig] = Field(min_length=1)
    policy: Policy = Policy()
    identity: IdentityConfig | None = Field(
        default=None,
        description="When set, the principal is derived from a verified token instead of `principal`.",
    )
    approval_ttl_seconds: int = Field(default=900, ge=0, le=86400)
    budget: BudgetConfig | None = None
    audit_path: str = Field(
        default=":memory:",
        description="Where the audit chain is written. The in-memory default is deliberate: a durable log is a deployment decision, and silently writing one into a user's home directory is not a decision to make on their behalf.",
    )

    def resolve_principal(self) -> Principal:
        """The principal this gateway acts for.

        A configured identity wins over the static `principal`, and a failure to
        establish it is fatal rather than a fallback: quietly dropping back to a
        config-file principal when a token is missing or invalid would mean the
        gateway granting access on the strength of a file instead of an identity
        provider -- the exact failure this layer exists to prevent.
        """
        if self.identity is None:
            return self.principal
        return self.identity.build_resolver().resolve(self.identity.credential())

    def build_resolver(self) -> PrincipalResolver:
        if self.identity is None:
            return StaticPrincipalResolver(self.principal)
        return self.identity.build_resolver()

    @classmethod
    def load(cls, path: Path | str) -> TurnstileConfig:
        raw: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(raw)

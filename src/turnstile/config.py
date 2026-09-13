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


class TurnstileConfig(BaseModel):
    """The whole gateway, declared in one file."""

    model_config = ConfigDict(frozen=True)

    principal: Principal
    """Who the gateway acts for.

    In this slice it is configured, because a stdio server is launched by one
    user's client and the transport has no authorization framework -- the
    specification says stdio implementations should take credentials from the
    environment rather than from the protocol. Deriving it from a real identity
    provider is the next layer, and it changes this field's source, not its
    meaning.
    """

    servers: dict[str, ServerConfig] = Field(min_length=1)
    policy: Policy = Policy()
    budget: BudgetConfig | None = None
    audit_path: str = Field(
        default=":memory:",
        description="Where the audit chain is written. The in-memory default is deliberate: a durable log is a deployment decision, and silently writing one into a user's home directory is not a decision to make on their behalf.",
    )

    @classmethod
    def load(cls, path: Path | str) -> TurnstileConfig:
        raw: dict[str, Any] = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(raw)

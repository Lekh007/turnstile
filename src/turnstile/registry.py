"""Aggregating several MCP servers behind one, and routing calls back.

A proxy that fronts more than one server has a naming problem the
specification names directly: two servers may each expose a `search`, and
"tool name uniqueness is scoped to a single server", so clients and proxies
that aggregate "SHOULD implement a disambiguation strategy such as prefixing
tool names with a server identifier".

Turnstile prefixes with `<server>.<tool>`. A dot is a legal tool-name
character, the result stays readable in a model's context, and routing is a
split on the *first* dot -- which is why `StdioUpstream` refuses a server name
containing one. Splitting on the first dot rather than the last is deliberate:
`admin.tools.list` is itself a legal tool name, so `files.admin.tools.list`
must resolve to server `files`, tool `admin.tools.list`.

The specification also notes that a server's self-reported `serverInfo` name is
not guaranteed unique and "SHOULD NOT be relied upon for disambiguation", so
the prefix comes from the operator's configuration, never from the upstream.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .upstream import Upstream, log

MAX_TOOL_NAME_LENGTH = 128
"""The specification's recommended ceiling. Exceeding it is warned about, not enforced:
refusing to expose a tool because its name grew two characters too long would
break a working integration over a SHOULD."""


@dataclass(frozen=True)
class Route:
    """Where a prefixed tool name points."""

    server: str
    tool: str
    """The tool's original, unprefixed name as the upstream knows it."""


class ToolRegistry:
    """Maps prefixed tool names to upstreams, and aggregates `tools/list`."""

    def __init__(self, upstreams: dict[str, Upstream]) -> None:
        self._upstreams = upstreams

    @property
    def server_names(self) -> list[str]:
        return sorted(self._upstreams)

    def upstream(self, name: str) -> Upstream | None:
        return self._upstreams.get(name)

    @staticmethod
    def qualify(server: str, tool: str) -> str:
        qualified = f"{server}.{tool}"
        if len(qualified) > MAX_TOOL_NAME_LENGTH:
            log(
                f"[turnstile] qualified tool name {qualified!r} exceeds the "
                f"{MAX_TOOL_NAME_LENGTH}-character guidance; exposing it anyway"
            )
        return qualified

    def resolve(self, qualified: str) -> Route | None:
        """Split a prefixed name back into its server and original tool.

        Returns None for a name with no prefix or an unknown server, so the
        caller can answer with a proper "unknown tool" error rather than
        guessing which upstream was meant. Guessing is how a call intended for
        `staging` lands on `prod`.
        """
        server, separator, tool = qualified.partition(".")
        if not separator or not tool:
            return None
        if server not in self._upstreams:
            return None
        return Route(server=server, tool=tool)

    def aggregate_tools(self, results: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        """Merge per-server `tools/list` results into one prefixed list.

        Order is deterministic -- servers sorted by name, tools kept in the
        order each server returned them. The specification asks servers to
        return tools in a stable order because clients cache the list and
        because a stable ordering improves prompt cache hit rates; an
        aggregator that shuffled them on every call would throw that away.
        """
        aggregated: list[dict[str, Any]] = []
        for server in sorted(results):
            tools = results[server].get("tools")
            if not isinstance(tools, list):
                continue
            for tool in tools:
                if not isinstance(tool, dict):
                    continue
                name = tool.get("name")
                if not isinstance(name, str) or not name:
                    continue
                aggregated.append({**tool, "name": self.qualify(server, name)})
        return aggregated

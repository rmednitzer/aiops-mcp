"""Tool registry: the MCP tool surface, decoupled from the transport.

Each tool is a ``ToolSpec`` with accurate ``read_only`` / ``destructive`` hints
(ADR-0006). Tool modules call ``register``; the server exposes the registry over a
transport (stdio today). Keeping the registry transport-agnostic means the same
specs can later back the official MCP SDK without touching tool logic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from praxis.context import ServerContext

ToolHandler = Callable[[dict[str, object], ServerContext], str]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    read_only: bool
    destructive: bool
    input_schema: dict[str, object]
    handler: ToolHandler

    def to_mcp(self) -> dict[str, object]:
        """Render as an MCP tool descriptor with annotation hints."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
            },
        }


@dataclass
class ToolRegistry:
    _specs: dict[str, ToolSpec] = field(default_factory=dict)

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._specs:
            raise ValueError(f"duplicate tool name: {spec.name}")
        self._specs[spec.name] = spec

    def names(self) -> list[str]:
        return sorted(self._specs)

    def specs(self) -> list[ToolSpec]:
        return [self._specs[name] for name in self.names()]

    def call(self, name: str, arguments: dict[str, object], ctx: ServerContext) -> str:
        spec = self._specs.get(name)
        if spec is None:
            raise KeyError(f"unknown tool: {name}")
        return spec.handler(arguments, ctx)

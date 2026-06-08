"""Tool registry: the MCP tool surface, decoupled from the transport.

Each tool is a ``ToolSpec`` whose ``args_model`` (a pydantic model) is the single
source of truth for both the advertised JSON Schema and the boundary validation of
incoming arguments (ADR-0006, ADR-0014). The registry validates a ``tools/call``
argument set through the model before dispatching, so an out-of-shape, missing, or
unexpected argument is rejected in one place at the trust boundary rather than in
each handler. Keeping the registry transport-agnostic means the same specs can later
back the official MCP SDK without touching tool logic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, ValidationError

from praxis.context import ServerContext


class ToolArgs(BaseModel):
    """Base model for a tool's validated input.

    Unknown arguments are rejected (``extra='forbid'``) so an unexpected field at the
    boundary fails closed instead of being silently ignored.
    """

    model_config = ConfigDict(extra="forbid")


ToolHandler = Callable[[Any, ServerContext], str]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    read_only: bool
    destructive: bool
    args_model: type[ToolArgs]
    handler: ToolHandler

    def input_schema(self) -> dict[str, object]:
        """The advertised JSON Schema, generated from the args model (one source)."""
        return dict(self.args_model.model_json_schema())

    def to_mcp(self) -> dict[str, object]:
        """Render as an MCP tool descriptor with annotation hints."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema(),
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
            },
        }


def tool_spec[M: ToolArgs](
    *,
    name: str,
    description: str,
    read_only: bool,
    destructive: bool,
    args_model: type[M],
    handler: Callable[[M, ServerContext], str],
) -> ToolSpec:
    """Build a ToolSpec, tying the handler to its args model at the call site.

    The generic ``M`` makes registration type-safe (a handler must accept its own
    model); storage erases to the base ``ToolArgs`` so the registry stays uniform.
    """
    return ToolSpec(
        name=name,
        description=description,
        read_only=read_only,
        destructive=destructive,
        args_model=args_model,
        handler=cast(ToolHandler, handler),
    )


class ToolError(ValueError):
    """A bounded, caller-facing tool error (for example invalid arguments)."""


def _summarize(exc: ValidationError) -> str:
    parts: list[str] = []
    for err in exc.errors()[:3]:
        loc = ".".join(str(p) for p in err["loc"]) or "(root)"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


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
        try:
            model = spec.args_model.model_validate(arguments)
        except ValidationError as exc:
            raise ToolError(f"invalid arguments for {name!r}: {_summarize(exc)}") from exc
        return spec.handler(model, ctx)

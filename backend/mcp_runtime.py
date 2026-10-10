"""Credential-bearing MCP instances live only for one request or scan job."""

import logging
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps


@dataclass
class MCPRuntime:
    servers: dict = field(default_factory=dict)
    plugins: dict = field(default_factory=dict)
    owner: str | None = None


_runtime: ContextVar[MCPRuntime | None] = ContextVar("mcp_runtime", default=None)


def current_runtime() -> MCPRuntime:
    runtime = _runtime.get()
    if runtime is None:
        runtime = MCPRuntime()
        _runtime.set(runtime)
    return runtime


def bind_mcp_owner(user_id: str) -> None:
    runtime = current_runtime()
    if runtime.owner is not None and runtime.owner != user_id:
        raise PermissionError("MCP runtime belongs to another user")
    runtime.owner = user_id


@asynccontextmanager
async def isolated_mcp_runtime():
    runtime = MCPRuntime()
    token = _runtime.set(runtime)
    try:
        yield runtime
    finally:
        for server in runtime.servers.values():
            try:
                await server.stop()
            except Exception:
                logging.getLogger(__name__).exception("MCP server cleanup failed")
        runtime.servers.clear()
        runtime.plugins.clear()
        _runtime.reset(token)


def isolated_scan(function):
    @wraps(function)
    async def wrapped(*args, **kwargs):
        async with isolated_mcp_runtime():
            return await function(*args, **kwargs)
    return wrapped

"""Versioned MCP result contracts and typed debugger failures."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

MCP_SCHEMA = "pygdbmi.mcp/1"
ERROR_SCHEMA = "pygdbmi.error/1"
CATALOG_REVISION = "2026-09-01.execution-topology.1"


class SessionSummary(TypedDict, total=False):
    session_id: str
    run_state: str
    stop_id: int
    last_stop: dict[str, Any] | None
    binary: str | None
    pid: int | None
    target_kind: str
    selected_thread: int | None
    selected_frame: int
    event_cursor: int
    created_at: float
    gdb_version: str | None
    architecture: str | None
    endianness: str | None
    pointer_width: int | None
    thread_group: str | None
    exit_code: str | None
    last_error: dict[str, Any] | None
    inferior_tty: str | None
    inferior_io_cursor: int
    inferior_io_base_cursor: int
    selected_inferior: int | None
    inferior_count: int
    active_inferior_count: int
    inferiors: list[dict[str, Any]]
    fork_policy: dict[str, Any]
    active_execution_jobs: list[str]
    capabilities_cached_at: float | None


class ErrorInfo(TypedDict):
    schema: Literal["pygdbmi.error/1"]
    code: str
    message: str
    operation: str
    retryable: bool
    details: dict[str, Any]
    recovery: list[str]


class ToolEnvelope(TypedDict):
    schema: Literal["pygdbmi.mcp/1"]
    ok: bool
    result: Any
    error: ErrorInfo | None
    session: SessionSummary | None


class CommandReply(TypedDict):
    command_id: int
    result_class: str
    payload: Any
    output: str
    output_chars: int
    next_offset: int | None
    truncated: bool
    notifications: list[dict[str, Any]]
    elapsed_ms: float


class GdbMcpError(RuntimeError):
    """Typed error carried through the MCP envelope."""

    def __init__(
        self,
        message: object,
        *,
        code: str = "operation_failed",
        retryable: bool = False,
        details: dict[str, Any] | None = None,
        recovery: list[str] | None = None,
    ) -> None:
        self.message = str(message)[:2048]
        self.code = _safe_code(code)
        self.retryable = bool(retryable)
        self.details = bounded_value(details or {}, max_string=2048)
        self.recovery = [str(item)[:512] for item in (recovery or [])[:3]]
        super().__init__(self.message)


class GdbCommandError(GdbMcpError):
    """GDB returned a tokened ``^error`` record."""


def _safe_code(value: object) -> str:
    code = str(value)
    if 1 <= len(code) <= 64 and all(
        char.islower() or char.isdigit() or char == "_" for char in code
    ):
        return code
    return "operation_failed"


def bounded_value(
    value: Any,
    *,
    max_string: int = 64 * 1024,
    max_items: int = 1024,
    depth: int = 0,
) -> Any:
    """Return a JSON-safe bounded copy of a pygdbmi/user payload."""

    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return (
            value if len(value) <= max_string else value[:max_string] + "...<truncated>"
        )
    if isinstance(value, bytes):
        text = value.hex()
        return text if len(text) <= max_string else text[:max_string] + "...<truncated>"
    if depth >= 8:
        return str(value)[:max_string]
    if isinstance(value, (list, tuple)):
        result = [
            bounded_value(
                item,
                max_string=max_string,
                max_items=max_items,
                depth=depth + 1,
            )
            for item in value[:max_items]
        ]
        if len(value) > max_items:
            result.append({"_truncated_items": len(value) - max_items})
        return result
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (raw_key, item) in enumerate(value.items()):
            if index >= max_items:
                result["_truncated_items"] = len(value) - max_items
                break
            result[str(raw_key)[:256]] = bounded_value(
                item,
                max_string=max_string,
                max_items=max_items,
                depth=depth + 1,
            )
        return result
    return str(value)[:max_string]


def ok_envelope(result: Any, session: SessionSummary | None = None) -> ToolEnvelope:
    return {
        "schema": MCP_SCHEMA,
        "ok": True,
        "result": bounded_value(result),
        "error": None,
        "session": bounded_value(session) if session is not None else None,
    }


def error_envelope(
    exc: BaseException | str,
    *,
    operation: str,
    session: SessionSummary | None = None,
) -> ToolEnvelope:
    if isinstance(exc, GdbMcpError):
        code = exc.code
        message = exc.message
        retryable = exc.retryable
        details = exc.details
        recovery = exc.recovery
    elif isinstance(exc, (TypeError, ValueError)):
        code = "invalid_argument"
        message = str(exc)
        retryable = False
        details = {"exception_type": type(exc).__name__}
        recovery = []
    elif isinstance(exc, TimeoutError):
        code = "timeout"
        message = str(exc)
        retryable = True
        details = {}
        recovery = ["Inspect session status and interrupt before retrying."]
    else:
        code = "internal_error"
        message = str(exc)
        retryable = False
        details = {"exception_type": type(exc).__name__}
        recovery = []
    return {
        "schema": MCP_SCHEMA,
        "ok": False,
        "result": None,
        "error": {
            "schema": ERROR_SCHEMA,
            "code": _safe_code(code),
            "message": message[:2048],
            "operation": operation[:128],
            "retryable": retryable,
            "details": bounded_value(details, max_string=2048),
            "recovery": recovery[:3],
        },
        "session": bounded_value(session) if session is not None else None,
    }

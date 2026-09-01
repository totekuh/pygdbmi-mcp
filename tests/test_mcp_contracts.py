"""Wire-contract, catalog, annotation, and state-matrix tests."""

from __future__ import annotations

import asyncio
import json
import threading

import pytest

from pygdbmi_mcp.contracts import (
    CATALOG_REVISION,
    GdbMcpError,
    bounded_value,
    error_envelope,
    ok_envelope,
)
from pygdbmi_mcp.server import (
    gdb_batch,
    gdb_command,
    gdb_context,
    gdb_memory,
    gdb_var_children,
    manager,
    mcp,
)


class StateStub:
    def __init__(self, state: str) -> None:
        self.run_state = state
        self.command_lock = threading.RLock()

    def status(self) -> dict:
        return {"session_id": "state-stub", "run_state": self.run_state, "stop_id": 4}


def test_success_envelope_has_stable_shape() -> None:
    envelope = ok_envelope({"answer": 42}, {"session_id": "gdb-1"})
    assert envelope == {
        "schema": "pygdbmi.mcp/1",
        "ok": True,
        "result": {"answer": 42},
        "error": None,
        "session": {"session_id": "gdb-1"},
    }


def test_typed_error_envelope_has_recovery_and_bounds() -> None:
    exc = GdbMcpError(
        "bad state",
        code="invalid_state",
        retryable=True,
        details={"blob": "X" * 5000},
        recovery=["interrupt", "wait", "retry", "ignored"],
    )
    envelope = error_envelope(exc, operation="gdb_context")
    assert envelope["ok"] is False
    assert envelope["error"]["schema"] == "pygdbmi.error/1"
    assert envelope["error"]["code"] == "invalid_state"
    assert envelope["error"]["retryable"] is True
    assert len(envelope["error"]["details"]["blob"]) < 2100
    assert envelope["error"]["recovery"] == ["interrupt", "wait", "retry"]


def test_unexpected_error_is_sanitized() -> None:
    envelope = error_envelope(RuntimeError("detonated"), operation="unit")
    assert envelope["error"]["code"] == "internal_error"
    assert envelope["error"]["details"] == {"exception_type": "RuntimeError"}


def test_recursive_payload_bounding_handles_depth_items_bytes_and_strings() -> None:
    value = {
        "bytes": b"\xde\xad",
        "items": list(range(20)),
        "text": "A" * 100,
        "deep": [[[[[[[[["bottom"]]]]]]]]],
    }
    bounded = bounded_value(value, max_string=16, max_items=4)
    assert bounded["bytes"] == "dead"
    assert bounded["items"][-1] == {"_truncated_items": 16}
    assert bounded["text"].endswith("...<truncated>")
    assert isinstance(bounded["deep"][0][0][0][0][0][0][0], str)


def test_missing_session_is_a_structured_error_not_an_exception() -> None:
    envelope = gdb_command("no-such-session", "help")
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "no_session"
    assert envelope["error"]["operation"] == "gdb_command"


def test_operation_matrix_rejects_stopped_only_tool_while_running() -> None:
    stub = StateStub("running")
    manager.sessions["state-stub"] = stub  # type: ignore[assignment]
    try:
        envelope = gdb_context("state-stub")
    finally:
        manager.sessions.pop("state-stub")
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "invalid_state"
    assert envelope["error"]["details"]["allowed_states"] == ["stopped"]


def test_direct_tool_bounds_fail_before_reaching_gdb() -> None:
    stub = StateStub("stopped")
    manager.sessions["state-stub"] = stub  # type: ignore[assignment]
    try:
        failed_calls = [
            gdb_memory("state-stub", "$sp", count=65536, word_size=8),
            gdb_batch("state-stub", []),
            gdb_batch("state-stub", "not-a-list"),  # type: ignore[arg-type]
            gdb_var_children("state-stub", "watch", 10, 9),
            gdb_var_children("state-stub", "watch", 0, 1000),
        ]
    finally:
        manager.sessions.pop("state-stub")
    assert all(item["error"]["code"] == "invalid_argument" for item in failed_calls)


def _tools():
    return asyncio.run(mcp.list_tools())


def test_catalog_identity_count_and_shared_structured_output() -> None:
    tools = _tools()
    assert len(tools) == 65
    assert CATALOG_REVISION == "2026-09-01.mcp-stability.1"
    assert len({tool.name for tool in tools}) == len(tools)
    assert all(
        tool.outputSchema and tool.outputSchema["type"] == "object" for tool in tools
    )
    # Regression guard: do not repeat the full result schema for every tool.
    output_schema_chars = sum(len(json.dumps(tool.outputSchema)) for tool in tools)
    assert output_schema_chars < 7000


def test_catalog_exposes_constraints_and_literal_enums() -> None:
    tools = {tool.name: tool for tool in _tools()}
    context = tools["gdb_context"].inputSchema["properties"]
    assert context["backtrace_depth"]["minimum"] == 1
    assert context["backtrace_depth"]["maximum"] == 64
    assert context["register_set"]["enum"] == ["general", "all"]
    memory = tools["gdb_memory"].inputSchema["properties"]
    assert memory["count"]["maximum"] == 65536
    assert memory["word_size"]["enum"] == [1, 2, 4, 8]
    stop = tools["gdb_stop"].inputSchema["properties"]
    assert stop["policy"]["enum"] == ["auto", "kill", "detach", "disconnect", "quit"]


@pytest.mark.parametrize(
    ("tool_name", "read_only", "destructive", "idempotent", "open_world"),
    [
        ("gdb_session_status", True, False, True, False),
        ("gdb_context", True, False, True, False),
        ("gdb_memory_write", False, True, False, False),
        ("gdb_start", False, True, False, True),
        ("gdb_command", False, True, False, True),
    ],
)
def test_tool_annotations(
    tool_name, read_only, destructive, idempotent, open_world
) -> None:
    tool = {item.name: item for item in _tools()}[tool_name]
    assert tool.annotations.readOnlyHint is read_only
    assert tool.annotations.destructiveHint is destructive
    assert tool.annotations.idempotentHint is idempotent
    assert tool.annotations.openWorldHint is open_world


def test_server_instructions_define_efficient_workflow() -> None:
    instructions = mcp.instructions
    assert "gdb_wait_for_stop" in instructions
    assert "gdb_context" in instructions
    assert "gdb_output_page" in instructions
    assert "check ok" in instructions

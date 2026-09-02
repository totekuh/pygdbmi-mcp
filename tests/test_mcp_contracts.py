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
    gdb_breakpoint,
    gdb_command,
    gdb_context,
    gdb_load_core,
    gdb_memory,
    gdb_rr_replay,
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


class CoreLoadStub(StateStub):
    def __init__(self, *, old_parser: bool, unrelated_error: bool = False) -> None:
        super().__init__("idle")
        self.old_parser = old_parser
        self.unrelated_error = unrelated_error
        self.commands: list[str] = []
        self.binary = None
        self.target_kind = "none"

    def execute(self, command: str, *, timeout_sec: float) -> dict:
        self.commands.append(command)
        if command.startswith('core-file "'):
            if self.unrelated_error:
                raise GdbMcpError("Permission denied", code="gdb_error")
            if self.old_parser:
                path = command.removeprefix("core-file ")
                raise GdbMcpError(
                    f"{path}: No such file or directory", code="gdb_error"
                )
        return {"result_class": "done", "payload": {}, "output": ""}

    def set_state(self, state: str, *, clear_stop: bool = False) -> None:
        self.run_state = state

    def refresh_target_traits(self) -> None:
        return None


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
            gdb_breakpoint("state-stub", locations=[]),
        ]
    finally:
        manager.sessions.pop("state-stub")
    assert all(item["error"]["code"] == "invalid_argument" for item in failed_calls)


@pytest.mark.parametrize("old_parser", [False, True])
def test_core_load_path_quoting_ab_across_gdb_generations(tmp_path, old_parser) -> None:
    stub = CoreLoadStub(old_parser=old_parser)
    manager.sessions["state-stub"] = stub  # type: ignore[assignment]
    core = str(tmp_path / "crash core with spaces")
    binary = str(tmp_path / "test binary")
    try:
        envelope = gdb_load_core("state-stub", core, binary)
    finally:
        manager.sessions.pop("state-stub")
    assert envelope["ok"] is True
    core_commands = [
        command for command in stub.commands if command.startswith("core-file")
    ]
    assert core_commands[0] == f'core-file "{core}"'
    assert core_commands == (
        [f'core-file "{core}"', f"core-file {core}"]
        if old_parser
        else [f'core-file "{core}"']
    )


def test_core_load_does_not_retry_unrelated_failure(tmp_path) -> None:
    stub = CoreLoadStub(old_parser=False, unrelated_error=True)
    manager.sessions["state-stub"] = stub  # type: ignore[assignment]
    try:
        envelope = gdb_load_core("state-stub", str(tmp_path / "crash core with spaces"))
    finally:
        manager.sessions.pop("state-stub")
    assert envelope["ok"] is False
    assert envelope["error"]["message"] == "Permission denied"
    assert len([item for item in stub.commands if item.startswith("core-file")]) == 1


def test_rr_adapter_reports_missing_executable(monkeypatch, tmp_path) -> None:
    stub = StateStub("idle")
    manager.sessions["state-stub"] = stub  # type: ignore[assignment]
    monkeypatch.setattr("pygdbmi_mcp.server.shutil.which", lambda _: None)
    try:
        envelope = gdb_rr_replay("state-stub", str(tmp_path))
    finally:
        manager.sessions.pop("state-stub")
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "adapter_unavailable"


def _tools():
    return asyncio.run(mcp.list_tools())


def test_catalog_identity_count_and_shared_structured_output() -> None:
    tools = _tools()
    assert len(tools) == 89
    assert CATALOG_REVISION == "2026-09-02.research-workflows.1"
    assert len({tool.name for tool in tools}) == len(tools)
    assert all(
        tool.outputSchema and tool.outputSchema["type"] == "object" for tool in tools
    )
    # Regression guard: do not repeat the full result schema for every tool.
    output_schema_chars = sum(len(json.dumps(tool.outputSchema)) for tool in tools)
    assert output_schema_chars < len(tools) * 100


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
    execution = tools["gdb_execution_start"].inputSchema["properties"]
    assert execution["action"]["enum"] == [
        "run",
        "continue",
        "step",
        "next",
        "finish",
        "until",
    ]
    assert execution["timeout_sec"]["minimum"] == 0
    assert execution["timeout_sec"]["maximum"] == 86400
    job_status = tools["gdb_execution_status"].inputSchema["properties"]
    assert job_status["wait_timeout"]["maximum"] == 300
    cancellation = tools["gdb_execution_cancel"].inputSchema["properties"]
    assert cancellation["timeout_sec"]["minimum"] == 0.05
    fork_policy = tools["gdb_fork_policy"].inputSchema["properties"]
    assert fork_policy["follow"]["enum"] == ["parent", "child"]
    trace = tools["gdb_log_breakpoint"].inputSchema["properties"]
    assert trace["limit"]["maximum"] == 100000
    assert trace["backtrace_depth"]["maximum"] == 64
    log_read = tools["gdb_log_read"].inputSchema["properties"]
    assert log_read["encoding"]["enum"] == ["json", "jsonl"]
    record = tools["gdb_record_start"].inputSchema["properties"]
    assert record["method"]["enum"] == ["auto", "full", "btrace"]
    reverse = tools["gdb_reverse"].inputSchema["properties"]
    assert reverse["action"]["enum"] == ["continue", "step", "next", "finish"]


@pytest.mark.parametrize(
    ("tool_name", "read_only", "destructive", "idempotent", "open_world"),
    [
        ("gdb_session_status", True, False, True, False),
        ("gdb_context", True, False, True, False),
        ("gdb_memory_write", False, True, False, False),
        ("gdb_start", False, True, False, True),
        ("gdb_command", False, True, False, True),
        ("gdb_execution_start", False, True, False, False),
        ("gdb_execution_status", True, False, True, False),
        ("gdb_execution_cancel", False, True, True, False),
        ("gdb_inferiors", True, False, True, False),
        ("gdb_fork_policy", False, True, True, False),
        ("gdb_capabilities", True, False, True, False),
        ("gdb_log_read", True, False, True, False),
        ("gdb_log_breakpoint", False, True, False, False),
        ("gdb_catch_crash", False, True, False, False),
        ("gdb_modules", True, False, True, True),
        ("gdb_load_symbols_json", False, True, False, True),
        ("gdb_debug_config", False, True, False, True),
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
    assert "gdb_execution_start" in instructions
    assert "gdb_execution_status" in instructions
    assert "gdb_capabilities" in instructions
    assert "gdb_inferiors" in instructions
    assert "gdb_log_breakpoint" in instructions
    assert "gdb_catch_crash" in instructions
    assert "gdb_modules" in instructions
    assert "check ok" in instructions

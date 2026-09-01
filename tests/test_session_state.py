"""Unit tests for the persistent MI dispatcher and session state machine."""

from __future__ import annotations

import os
import re
import select
import threading
import time
from collections import deque
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from pygdbmi_mcp.contracts import GdbCommandError, GdbMcpError
from pygdbmi_mcp.runtime import (
    MAX_EVENTS,
    MAX_INFERIOR_IO,
    GdbManager,
    GdbSession,
    _wire_command,
    cli_quote,
    mi_quote,
)


class FakeController:
    """A blocking fake with the same ownership contract as pygdbmi."""

    def __init__(self, command=None) -> None:
        self.condition = threading.Condition()
        self.records: deque[dict] = deque()
        self.writes: list[str] = []
        self.handler: Callable[[int, str], None] | None = None
        self.gdb_process = SimpleNamespace(pid=999_999_999)
        self.exited = False
        self.fail_reader: BaseException | None = None
        self.command = command
        self.active_writes = 0
        self.max_active_writes = 0

    def write(self, command: str, *args, **kwargs) -> list[dict]:
        match = re.match(r"^(\d+)(.*)$", command)
        assert match is not None, f"missing runtime-owned token: {command!r}"
        token, wire = int(match.group(1)), match.group(2)
        with self.condition:
            self.writes.append(command)
            self.active_writes += 1
            self.max_active_writes = max(self.max_active_writes, self.active_writes)
        try:
            if self.handler is None:
                self.emit(result(token, "done"))
            else:
                self.handler(token, wire)
        finally:
            with self.condition:
                self.active_writes -= 1
        return []

    def emit(self, *records: dict) -> None:
        with self.condition:
            self.records.extend(records)
            self.condition.notify_all()

    def get_gdb_response(self, timeout_sec=0.1, **kwargs) -> list[dict]:
        with self.condition:
            if self.fail_reader is not None:
                raise self.fail_reader
            if not self.records and not self.exited:
                self.condition.wait(min(float(timeout_sec), 0.05))
            items = list(self.records)
            self.records.clear()
            return items

    def exit(self) -> None:
        with self.condition:
            self.exited = True
            self.condition.notify_all()


def record(record_type: str, message: str, payload=None, token=None) -> dict:
    return {
        "type": record_type,
        "message": message,
        "payload": payload,
        "token": token,
        "stream": "stdout",
    }


def result(token: int, message: str, payload=None) -> dict:
    return record("result", message, payload, token)


@pytest.fixture()
def fake_session():
    fake = FakeController()
    session = GdbSession(fake, "unit-1")  # type: ignore[arg-type]
    yield fake, session
    session.close("quit")


def test_token_correlates_result_and_routes_streams(fake_session) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        assert wire == "-gdb-version"
        fake.emit(
            record("console", None, "version line\n"),
            result(token + 900, "done", {"wrong": True}),
            result(token, "done", {"right": True}),
        )

    fake.handler = handler
    reply = session.execute("-gdb-version")
    assert reply["payload"] == {"right": True}
    assert reply["output"] == "version line\n"
    assert reply["command_id"] == 1
    assert fake.writes == ["1-gdb-version"]


def test_gdb_error_is_typed_and_retains_reply(fake_session) -> None:
    fake, session = fake_session
    fake.handler = lambda token, wire: fake.emit(
        result(token, "error", {"msg": "No symbol nope"})
    )
    with pytest.raises(GdbCommandError, match="No symbol nope") as caught:
        session.execute('-data-evaluate-expression "nope"')
    assert caught.value.code == "gdb_error"
    assert caught.value.details["reply"]["result_class"] == "error"
    assert session.last_error["code"] == "gdb_error"


def test_tracks_running_stop_exit_and_target_identity(fake_session) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        fake.emit(
            result(token, "running"),
            record("exec", "running", {"thread-id": "all"}),
            record("notify", "thread-group-started", {"id": "i1", "pid": "4242"}),
            record(
                "exec",
                "stopped",
                {"reason": "breakpoint-hit", "thread-id": "7"},
            ),
        )

    fake.handler = handler
    session.execute("-exec-run")
    assert session.run_state == "stopped"
    assert session.stop_id == 1
    assert session.selected_thread == 7
    assert session.thread_group == "i1"
    assert session.pid == 4242

    fake.emit(record("notify", "thread-group-exited", {"id": "i1", "exit-code": "0"}))
    deadline = time.monotonic() + 1
    while session.run_state != "exited" and time.monotonic() < deadline:
        time.sleep(0.005)
    assert session.run_state == "exited"
    assert session.exit_code == "0"


def test_output_first_page_and_followup_page(fake_session) -> None:
    fake, session = fake_session
    output = "A" * 900
    fake.handler = lambda token, wire: fake.emit(
        record("console", None, output), result(token, "done")
    )
    reply = session.execute("help", output_page_chars=256)
    assert reply["output"] == "A" * 256
    assert reply["truncated"] is True
    assert reply["next_offset"] == 256
    page = session.output_page(reply["command_id"], 256, 300)
    assert page["output"] == "A" * 300
    assert page["next_offset"] == 556
    tail = session.output_page(reply["command_id"], 556, 1000)
    assert tail["output"] == "A" * 344
    assert tail["next_offset"] is None


def test_event_payload_bounded_and_cursor_eviction(fake_session) -> None:
    _, session = fake_session
    for index in range(MAX_EVENTS + 8):
        session._route_record(
            record("notify", "thread-created", {"id": str(index), "text": "A" * 70000})
        )
    page = session.events(after_cursor=0, limit=10)
    assert page["cursor_gap"] is True
    assert page["events"][0]["cursor"] == 9
    assert page["truncated"] is True
    assert page["events"][0]["record"]["payload"]["text"].endswith("...<truncated>")


def test_wait_for_stop_ab_timeout_and_stop(fake_session) -> None:
    _, session = fake_session
    baseline = session.wait_for_stop(after_stop_id=0, timeout_sec=0)
    assert baseline["reason"] == "timeout"
    session.mark_synthetic_stop({"reason": "unit-test"})
    stopped = session.wait_for_stop(after_stop_id=0, timeout_sec=0)
    assert stopped["reason"] == "stopped"
    assert stopped["session"]["stop_id"] == 1


def test_command_timeout_marks_state_and_late_result_does_not_poison_next(
    fake_session,
) -> None:
    fake, session = fake_session
    tokens: list[int] = []

    def handler(token: int, wire: str) -> None:
        tokens.append(token)
        if len(tokens) > 1:
            fake.emit(result(token, "done", {"fresh": True}))

    fake.handler = handler
    with pytest.raises(GdbMcpError) as caught:
        session.execute("-slow", timeout_sec=0.05)
    assert caught.value.code == "timeout"
    assert session.run_state == "indeterminate"
    fake.emit(result(tokens[0], "done", {"late": True}))
    second = session.execute("-fresh", timeout_sec=1)
    assert second["payload"] == {"fresh": True}


def test_reader_failure_wakes_pending_command(fake_session) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        with fake.condition:
            fake.fail_reader = RuntimeError("pipe died")
            fake.condition.notify_all()

    fake.handler = handler
    with pytest.raises(GdbMcpError, match="reader failed") as caught:
        session.execute("-broken", timeout_sec=1)
    assert caught.value.code == "gdb_unreachable"
    assert session.run_state == "indeterminate"


def test_concurrent_commands_are_serialized(fake_session) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        time.sleep(0.04)
        fake.emit(result(token, "done", {"wire": wire}))

    fake.handler = handler
    barrier = threading.Barrier(3)
    replies: list[dict] = []

    def worker(command: str) -> None:
        barrier.wait()
        replies.append(session.execute(command, timeout_sec=1))

    threads = [
        threading.Thread(target=worker, args=(f"-cmd-{index}",)) for index in range(2)
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads)
    assert fake.max_active_writes == 1
    assert sorted(reply["command_id"] for reply in replies) == [1, 2]


def test_auto_cleanup_policy_matches_target_kind() -> None:
    fake = FakeController()
    session = GdbSession(fake, "unit-cleanup")  # type: ignore[arg-type]
    session.target_kind = "attached"
    cleanup = session.close("auto")
    assert cleanup["applied_policy"] == "detach"
    assert any(write.endswith("-target-detach") for write in fake.writes)
    assert fake.exited is True


def test_auto_cleanup_does_not_kill_a_loaded_but_unstarted_target() -> None:
    fake = FakeController()
    session = GdbSession(fake, "unit-loaded")  # type: ignore[arg-type]
    session.target_kind = "local"
    cleanup = session.close("auto")
    assert cleanup["applied_policy"] == "quit"
    assert fake.writes == []


def test_manager_forces_mi_mode_last_and_preserves_safe_gdb_args() -> None:
    created: list[FakeController] = []

    def factory(**kwargs):
        controller = FakeController(**kwargs)
        created.append(controller)
        return controller

    local_manager = GdbManager(controller_factory=factory)  # type: ignore[arg-type]
    sid = local_manager.create(
        gdb_args=["--readnow"], inferior_args=["space arg", 'quote"arg']
    )
    assert created[0].command == [
        "gdb",
        "--readnow",
        "--nx",
        "--quiet",
        "--interpreter=mi3",
    ]
    assert local_manager.get(sid).inferior_args == ["space arg", 'quote"arg']
    local_manager.destroy(sid, policy="quit")


@pytest.mark.parametrize(
    "gdb_args",
    [["--interpreter=console"], ["--args"], ["-x"], ["--pid=1"]],
)
def test_manager_rejects_gdb_args_that_break_managed_mi(gdb_args) -> None:
    local_manager = GdbManager(controller_factory=FakeController)  # type: ignore[arg-type]
    with pytest.raises(GdbMcpError) as caught:
        local_manager.create(gdb_args=gdb_args)
    assert caught.value.code == "invalid_argument"


@pytest.mark.parametrize(
    "inferior_args",
    [["x"] * 257, ["x" * 4097], ["nul\x00arg"]],
)
def test_manager_bounds_inferior_argument_vectors(inferior_args) -> None:
    local_manager = GdbManager(controller_factory=FakeController)  # type: ignore[arg-type]
    with pytest.raises(GdbMcpError) as caught:
        local_manager.create(inferior_args=inferior_args)
    assert caught.value.code == "invalid_argument"


def test_inferior_pty_cursor_reads_encodings_and_stdin() -> None:
    fake = FakeController()
    session = GdbSession(fake, "unit-pty", inferior_tty=True)  # type: ignore[arg-type]
    session._open_inferior_tty()
    try:
        assert session.inferior_tty_path
        assert session._pty_slave is not None
        os.write(session._pty_slave, b"hello")
        page = session.inferior_io(after_cursor=0, limit=5, wait_timeout=1)
        assert page["output"] == "hello"
        assert page["next_cursor"] == 5
        hexadecimal = session.inferior_io(after_cursor=0, limit=5, encoding="hex")
        assert hexadecimal["output"] == "68656c6c6f"

        written = session.write_inferior("input-line\n")
        assert written["bytes_written"] == 11
        readable, _, _ = select.select([session._pty_slave], [], [], 1)
        assert readable
        assert os.read(session._pty_slave, 64) == b"input-line\n"
    finally:
        session.close("quit")


def test_inferior_pty_eviction_gap_and_bounds() -> None:
    fake = FakeController()
    session = GdbSession(fake, "unit-pty-gap", inferior_tty=True)  # type: ignore[arg-type]
    session._open_inferior_tty()
    try:
        session._append_inferior_output(b"A" * (MAX_INFERIOR_IO + 10))
        page = session.inferior_io(after_cursor=0, limit=16)
        assert page["cursor_gap"] is True
        assert page["start_cursor"] == 10
        assert page["output"] == "A" * 16
        with pytest.raises(GdbMcpError):
            session.inferior_io(limit=0)
        with pytest.raises(GdbMcpError):
            session.write_inferior("")
        with pytest.raises(GdbMcpError):
            session.write_inferior("bad", encoding="hex")
    finally:
        session.close("quit")


def test_inferior_io_requires_pty(fake_session) -> None:
    _, session = fake_session
    with pytest.raises(GdbMcpError) as caught:
        session.inferior_io()
    assert caught.value.code == "pty_unavailable"


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda session: session.events(after_cursor=-1), "after_cursor"),
        (lambda session: session.events(limit=0), "limit"),
        (
            lambda session: session.wait_for_stop(after_stop_id=-1, timeout_sec=0),
            "stop_id",
        ),
        (lambda session: session.output_page(0, 0, 256), "command_id"),
        (lambda session: session.output_page(1, -1, 256), "offset"),
        (
            lambda session: session.execute("x", output_page_chars=1),
            "output_page_chars",
        ),
    ],
)
def test_runtime_bounds_reject_edges(fake_session, call, message) -> None:
    _, session = fake_session
    with pytest.raises(GdbMcpError, match=message):
        call(session)


@pytest.mark.parametrize(
    ("raw", "mode", "expected"),
    [
        ("-gdb-version", "auto", "-gdb-version"),
        ("show version", "auto", '-interpreter-exec console "show version"'),
        ("show version", "console", '-interpreter-exec console "show version"'),
    ],
)
def test_wire_command_ab_modes(raw, mode, expected) -> None:
    assert _wire_command(raw, mode) == expected


@pytest.mark.parametrize("raw", ["", "help\nquit", "12-gdb-version"])
def test_wire_command_rejects_empty_multiline_and_tokens(raw) -> None:
    with pytest.raises(GdbMcpError):
        _wire_command(raw, "auto")


def test_mi_and_cli_quoting_edge_cases() -> None:
    value = 'dir with spaces/quote"/slash\\/snowman-☃'
    assert mi_quote(value) == '"dir with spaces/quote\\"/slash\\\\/snowman-\\u2603"'
    assert cli_quote(value) == '"dir with spaces/quote\\"/slash\\\\/snowman-☃"'

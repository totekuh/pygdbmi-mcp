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
    MAX_EXECUTION_JOBS,
    MAX_INFERIOR_IO,
    GdbManager,
    GdbSession,
    _LogBreakpoint,
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
            record("notify", "library-loaded", {"id": "/tmp/libprobe.so"}),
            result(token + 900, "done", {"wrong": True}),
            result(token, "done", {"right": True}),
        )

    fake.handler = handler
    reply = session.execute("-gdb-version")
    assert reply["payload"] == {"right": True}
    assert reply["output"] == "version line\n"
    assert reply["command_id"] == 1
    assert reply["notification_count"] == 1
    assert reply["notification_summary"] == {"notify:library-loaded": 1}
    assert reply["event_cursor_end"] > reply["event_cursor_start"]
    assert fake.writes == ["1-gdb-version"]


def test_crash_signal_policy_and_evidence_bounds(fake_session) -> None:
    _, session = fake_session
    assert session._parse_signal_policy(
        "SIGSEGV",
        "Signal Stop Print Pass to program Description\nSIGSEGV Yes No Yes Segmentation fault\n",
    ) == (True, False, True)
    assert session._validate_crash_collect(
        ["backtrace", "registers", "memory:(char *)$sp,0x40"]
    ) == ["backtrace", "registers", "memory:(char *)$sp,64"]
    with pytest.raises(GdbMcpError, match="4096"):
        session._validate_crash_collect(["memory:$sp,4097"])


def test_crash_policy_restore_verifies_remote_side_effect_after_error(
    fake_session,
) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        if "handle SIGUSR1 nostop noprint pass" in wire:
            fake.emit(
                result(
                    token,
                    "error",
                    {"msg": "Cannot execute this command while the target is running."},
                )
            )
        elif "info handle SIGUSR1" in wire:
            fake.emit(
                record(
                    "console",
                    None,
                    "Signal Stop Print Pass to program Description\n"
                    "SIGUSR1 No No Yes User defined signal 1\n",
                ),
                result(token, "done"),
            )
        else:
            raise AssertionError(wire)

    fake.handler = handler
    job = SimpleNamespace(
        signal_policy_restored=False,
        restore_signal_commands=("handle SIGUSR1 nostop noprint pass",),
    )
    assert session._restore_crash_signal_policy(job) == []
    assert job.signal_policy_restored is True


def test_crash_watch_rejects_running_state_before_touching_signal_policy(
    fake_session,
) -> None:
    fake, session = fake_session
    session.run_state = "running"
    with pytest.raises(GdbMcpError) as caught:
        session.start_crash_watch(
            signals=["SIGUSR1"], collect=["backtrace"], timeout_sec=1
        )
    assert caught.value.code == "invalid_state"
    assert fake.writes == []


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


def test_multi_inferior_exit_does_not_fake_global_exit(fake_session) -> None:
    _, session = fake_session
    for group_id, pid, thread_id in (("i1", "4101", "1"), ("i2", "4102", "2")):
        session._route_record(record("notify", "thread-group-added", {"id": group_id}))
        session._route_record(
            record(
                "notify",
                "thread-group-started",
                {"id": group_id, "pid": pid},
            )
        )
        session._route_record(
            record(
                "notify",
                "thread-created",
                {"id": thread_id, "group-id": group_id},
            )
        )
    session._route_record(record("exec", "running", {"thread-id": "all"}))
    session._route_record(
        record("notify", "thread-group-exited", {"id": "i2", "exit-code": "027"})
    )
    session._route_record(
        record(
            "exec",
            "stopped",
            {"reason": "exited", "thread-id": "2", "exit-code": "027"},
        )
    )
    assert session.run_state == "stopped"
    topology = session.inferiors(refresh=False)
    states = {item["group_id"]: item["state"] for item in topology["inferiors"]}
    assert states == {"i1": "running", "i2": "exited"}
    assert topology["active_count"] == 1

    session._route_record(
        record("notify", "thread-group-exited", {"id": "i1", "exit-code": "0"})
    )
    assert session.run_state == "exited"
    assert session.status()["active_inferior_count"] == 0


def test_inferior_refresh_replaces_stale_threads_and_reconciles_states(
    fake_session,
) -> None:
    fake, session = fake_session
    session.run_state = "stopped"
    stale = session._ensure_inferior("i1")
    stale.threads.update({"1", "99"})
    session._thread_to_group.update({"1": "i1", "99": "i1"})
    session._ensure_inferior("i2").state = "running"

    fake.handler = lambda token, wire: fake.emit(
        result(
            token,
            "done",
            {
                "current-thread-id": "1",
                "groups": [
                    {
                        "id": "i1",
                        "pid": "4201",
                        "executable": "/tmp/one",
                        "threads": [{"id": "1", "state": "stopped"}],
                    },
                    {
                        "id": "i2",
                        "pid": "4202",
                        "exit-code": "9",
                        "threads": [],
                    },
                ],
            },
        )
    )
    topology = session.inferiors()
    items = {item["group_id"]: item for item in topology["inferiors"]}
    assert items["i1"]["threads"] == ["1"]
    assert items["i1"]["state"] == "stopped"
    assert items["i2"]["state"] == "exited"
    assert items["i2"]["exit_code"] == "9"
    assert "99" not in session._thread_to_group
    assert topology["selected_inferior"] == 1
    assert topology["active_count"] == 1


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


def test_execution_job_long_poll_observes_later_stop(fake_session) -> None:
    fake, session = fake_session
    session.run_state = "idle"

    def handler(token: int, wire: str) -> None:
        assert wire == "-exec-run"
        fake.emit(
            result(token, "running"), record("exec", "running", {"thread-id": "all"})
        )

    fake.handler = handler
    job = session.start_execution("run")
    assert job["state"] == "running"
    unchanged = session.execution_status(
        job["job_id"], after_revision=job["revision"], wait_timeout=0
    )
    assert unchanged["revision"] == job["revision"]

    timer = threading.Timer(
        0.03,
        fake.emit,
        args=(
            record(
                "exec",
                "stopped",
                {"reason": "breakpoint-hit", "thread-id": "1"},
            ),
        ),
    )
    timer.start()
    stopped = session.execution_status(
        job["job_id"], after_revision=job["revision"], wait_timeout=1
    )
    timer.join(timeout=1)
    assert stopped["state"] == "stopped"
    assert stopped["revision"] > job["revision"]
    assert stopped["stop_id"] == 1
    assert session.list_executions() == {
        "jobs": [stopped],
        "count": 1,
        "active_count": 0,
        "terminal_count": 1,
        "retention_limit": MAX_EXECUTION_JOBS,
    }


def test_execution_timeout_leaves_target_running_then_cancel_interrupts(
    fake_session,
) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        if wire == "-exec-run":
            fake.emit(
                result(token, "running"),
                record("exec", "running", {"thread-id": "all"}),
            )
        elif wire == "-exec-interrupt --all":
            fake.emit(
                result(token, "done"),
                record(
                    "exec",
                    "stopped",
                    {"reason": "signal-received", "thread-id": "1"},
                ),
            )
        else:
            raise AssertionError(wire)

    fake.handler = handler
    job = session.start_execution("run", timeout_sec=0.03)
    timed_out = session.execution_status(
        job["job_id"], after_revision=job["revision"], wait_timeout=1
    )
    assert timed_out["state"] == "timed_out"
    assert timed_out["error"]["code"] == "execution_timeout"
    assert session.run_state == "running"
    assert not any(write.endswith("-exec-interrupt --all") for write in fake.writes)

    cancelled = session.cancel_execution(job["job_id"], timeout_sec=1)
    assert cancelled["already_terminal"] is False
    assert cancelled["job"]["state"] == "cancelled"
    assert cancelled["job"]["cancel_requested"] is True
    assert session.run_state == "stopped"
    again = session.cancel_execution(job["job_id"], timeout_sec=1)
    assert again["already_terminal"] is True


def test_failed_interrupt_terminalizes_cancelling_job(fake_session) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        if wire == "-exec-run":
            fake.emit(
                result(token, "running"),
                record("exec", "running", {"thread-id": "all"}),
            )
        elif wire == "-exec-interrupt --all":
            # Some remote stubs acknowledge the request but never report a stop.
            fake.emit(result(token, "done"))
        else:
            raise AssertionError(wire)

    fake.handler = handler
    job = session.start_execution("run", timeout_sec=0.02)
    timed_out = session.execution_status(
        job["job_id"], after_revision=job["revision"], wait_timeout=1
    )
    assert timed_out["state"] == "timed_out"

    with pytest.raises(GdbMcpError) as caught:
        session.cancel_execution(job["job_id"], timeout_sec=0.05)
    assert caught.value.code == "interrupt_timeout"
    failed_job = caught.value.details["job"]
    assert failed_job["state"] == "failed"
    assert failed_job["error"]["code"] == "cancel_failed"
    assert failed_job["error"]["cause"]["code"] == "interrupt_timeout"
    assert session.list_executions()["active_count"] == 0


def test_interrupt_racing_managed_log_action_publishes_hidden_stop(
    fake_session,
) -> None:
    fake, session = fake_session
    trace = _LogBreakpoint(
        log_id="log-1",
        breakpoint_number="1",
        location="tick",
        expressions=("value",),
        condition="",
        hit_limit=10,
        backtrace_depth=0,
    )
    session._log_breakpoints[trace.log_id] = trace
    session._breakpoint_logs[trace.breakpoint_number] = trace.log_id
    session.run_state = "running"
    action_threads: list[threading.Thread] = []
    stop = {
        "reason": "breakpoint-hit",
        "bkptno": "1",
        "thread-id": "1",
        "stopped-threads": "all",
        "frame": {"addr": "0x401000", "func": "tick"},
    }

    def handler(token: int, wire: str) -> None:
        if wire == "-exec-interrupt --all":
            fake.emit(result(token, "done"))
            thread = threading.Thread(
                target=session._process_log_hit, args=(trace.log_id, stop)
            )
            action_threads.append(thread)
            thread.start()
        elif wire == '-data-evaluate-expression "value"':
            fake.emit(result(token, "done", {"value": "7"}))
        else:
            raise AssertionError(wire)

    fake.handler = handler
    interrupted = session.interrupt(timeout_sec=1)
    for thread in action_threads:
        thread.join(timeout=1)
    assert interrupted["reason"] == "stopped"
    assert session.run_state == "stopped"
    assert session.stop_id == 1
    assert session.last_stop["managed-action-interrupted"] is True
    assert trace.hit_count == 1
    assert not any(write.endswith("-exec-continue") for write in fake.writes)


def test_failed_execution_is_retained_with_job_id(fake_session) -> None:
    fake, session = fake_session
    fake.handler = lambda token, wire: fake.emit(
        result(token, "error", {"msg": "Cannot execute"})
    )
    with pytest.raises(GdbMcpError) as caught:
        session.start_execution("run")
    assert caught.value.code == "gdb_error"
    job_id = caught.value.details["job_id"]
    retained = session.execution_status(job_id)
    assert retained["state"] == "failed"
    assert retained["error"] == {"code": "gdb_error", "message": "Cannot execute"}


def test_execution_retention_prunes_oldest_terminal_job(fake_session) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        fake.emit(
            result(token, "running"),
            record("exec", "running", {"thread-id": "all"}),
            record("exec", "stopped", {"reason": "end-stepping-range"}),
        )

    fake.handler = handler
    for _ in range(MAX_EXECUTION_JOBS + 1):
        assert session.start_execution("run")["state"] == "stopped"
    listing = session.list_executions()
    assert listing["count"] == MAX_EXECUTION_JOBS
    assert listing["jobs"][0]["job_id"] == "exec-2"
    assert listing["jobs"][-1]["job_id"] == f"exec-{MAX_EXECUTION_JOBS + 1}"
    with pytest.raises(GdbMcpError) as caught:
        session.execution_status("exec-1")
    assert caught.value.code == "execution_not_found"


@pytest.mark.parametrize(
    ("call", "code"),
    [
        (lambda session: session.start_execution("warp"), "invalid_argument"),
        (lambda session: session.start_execution("until"), "invalid_argument"),
        (
            lambda session: session.start_execution("run", location="main"),
            "invalid_argument",
        ),
        (
            lambda session: session.start_execution("run", instruction="yes"),  # type: ignore[arg-type]
            "invalid_argument",
        ),
        (
            lambda session: session.start_execution("until", location="main\nquit"),
            "invalid_argument",
        ),
        (
            lambda session: session.start_execution("run", timeout_sec=-1),
            "invalid_argument",
        ),
        (
            lambda session: session.execution_status("missing"),
            "execution_not_found",
        ),
        (
            lambda session: session.execution_status("exec-1", after_revision=-1),
            "invalid_argument",
        ),
        (
            lambda session: session.cancel_execution("exec-1", timeout_sec=0),
            "invalid_argument",
        ),
    ],
)
def test_execution_job_edge_validation(fake_session, call, code) -> None:
    _, session = fake_session
    with pytest.raises(GdbMcpError) as caught:
        call(session)
    assert caught.value.code == code


def test_session_close_cancels_active_execution_job(fake_session) -> None:
    fake, session = fake_session
    fake.handler = lambda token, wire: fake.emit(
        result(token, "running"), record("exec", "running", {"thread-id": "all"})
    )
    job = session.start_execution("run")
    session.target_kind = "none"
    session.close("quit")
    retained = session.execution_status(job["job_id"])
    assert retained["state"] == "cancelled"
    assert retained["error"]["code"] == "session_closed"


def test_capabilities_cache_refresh_and_running_policy(fake_session) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        if wire == "-list-features":
            fake.emit(result(token, "done", {"features": ["frozen-varobjs", "async"]}))
        elif wire == "-list-target-features":
            fake.emit(result(token, "done", {"features": ["async"]}))
        elif "show osabi" in wire:
            fake.emit(
                record(
                    "console",
                    None,
                    'The current OS ABI is "auto" (currently "GNU/Linux").\n',
                ),
                result(token, "done"),
            )
        elif "show non-stop" in wire:
            fake.emit(
                record(
                    "console",
                    None,
                    "Controlling the inferior in non-stop mode is off.\n",
                ),
                result(token, "done"),
            )
        elif wire.startswith("-info-gdb-mi-command"):
            fake.emit(result(token, "done", {"command": {"exists": "true"}}))
        else:
            raise AssertionError(wire)

    fake.handler = handler
    first = session.capabilities()
    write_count = len(fake.writes)
    assert first["cached"] is False
    assert first["osabi"] == "GNU/Linux"
    assert first["osabi_setting"] == "auto"
    assert first["mi_features"] == ["async", "frozen-varobjs"]
    assert all(first["mi_commands"].values())

    second = session.capabilities()
    assert second["cached"] is True
    assert second["discovered_at"] == first["discovered_at"]
    assert len(fake.writes) == write_count

    session.run_state = "running"
    assert session.capabilities()["cached"] is True
    with pytest.raises(GdbMcpError) as caught:
        session.capabilities(refresh=True)
    assert caught.value.code == "invalid_state"
    session.run_state = "stopped"
    refreshed = session.capabilities(refresh=True)
    assert refreshed["cached"] is False
    assert len(fake.writes) == write_count * 2
    session.invalidate_capabilities()
    assert session.status()["capabilities_cached_at"] is None

    barrier = threading.Barrier(3)
    concurrent: list[dict] = []

    def discover() -> None:
        barrier.wait()
        concurrent.append(session.capabilities())

    threads = [threading.Thread(target=discover) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads)
    assert sorted(item["cached"] for item in concurrent) == [False, True]
    assert len(fake.writes) == write_count * 3


def test_capabilities_degrade_per_probe_instead_of_losing_manifest(
    fake_session,
) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        if wire == "-list-target-features":
            fake.emit(result(token, "error", {"msg": "unsupported"}))
        elif wire.startswith("-list-"):
            fake.emit(result(token, "done", {"features": []}))
        elif wire.startswith("-info-gdb-mi-command"):
            fake.emit(result(token, "done", {"command": {"exists": "false"}}))
        else:
            fake.emit(result(token, "done"))

    fake.handler = handler
    capabilities = session.capabilities()
    assert capabilities["cached"] is False
    assert capabilities["target_features"] == []
    assert capabilities["errors"]["target_features"] == "gdb_error: unsupported"
    assert not any(capabilities["mi_commands"].values())


def test_fork_policy_rolls_back_partial_failure(fake_session) -> None:
    fake, session = fake_session

    def handler(token: int, wire: str) -> None:
        if wire == "-gdb-set detach-on-fork off":
            fake.emit(result(token, "error", {"msg": "detach setting rejected"}))
        else:
            fake.emit(result(token, "done"))

    fake.handler = handler
    with pytest.raises(GdbMcpError) as caught:
        session.set_fork_policy(
            follow="child", detach_on_fork=False, schedule_multiple=True
        )
    assert caught.value.code == "gdb_error"
    assert caught.value.details["applied_before_failure"] == ["follow"]
    assert caught.value.details["rollback_errors"] == []
    assert session.fork_policy == {
        "follow": "parent",
        "detach_on_fork": True,
        "schedule_multiple": False,
    }
    assert [re.match(r"^\d+(.*)$", write).group(1) for write in fake.writes] == [
        "-gdb-set follow-fork-mode child",
        "-gdb-set detach-on-fork off",
        "-gdb-set follow-fork-mode parent",
    ]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"follow": "neither", "detach_on_fork": True, "schedule_multiple": False},
        {"follow": "parent", "detach_on_fork": "yes", "schedule_multiple": False},
        {"follow": "parent", "detach_on_fork": True, "schedule_multiple": 1},
    ],
)
def test_fork_policy_rejects_invalid_edges(fake_session, kwargs) -> None:
    _, session = fake_session
    with pytest.raises(GdbMcpError) as caught:
        session.set_fork_policy(**kwargs)
    assert caught.value.code == "invalid_argument"


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

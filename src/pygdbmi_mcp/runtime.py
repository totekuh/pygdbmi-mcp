"""Persistent token-correlated GDB/MI runtime.

One reader thread owns every read from a GDB process. Commands are serialized,
prefixed with numeric MI tokens, and completed only by their matching result
record. Asynchronous records are retained independently for cursor polling.
"""

from __future__ import annotations

import base64
import errno
import json
import os
import pty
import re
import select
import shutil
import signal
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pygdbmi.gdbcontroller import GdbController

from .contracts import (
    CommandReply,
    GdbCommandError,
    GdbMcpError,
    SessionSummary,
    bounded_value,
)

RunState = Literal["idle", "running", "stopped", "exited", "indeterminate"]
TargetKind = Literal["none", "local", "attached", "remote", "core"]
JobState = Literal[
    "starting",
    "running",
    "cancelling",
    "stopped",
    "exited",
    "cancelled",
    "timed_out",
    "failed",
    "collecting",
    "crashed",
    "unexpected_stop",
]

MAX_EVENTS = 1024
MAX_EVENT_STRING = 64 * 1024
MAX_COMMAND_OUTPUT = 1024 * 1024
DEFAULT_OUTPUT_PAGE = 16 * 1024
MAX_OUTPUT_PAGE = 64 * 1024
MAX_STORED_OUTPUTS = 32
MAX_NOTIFICATIONS = 128
MAX_INFERIOR_IO = 1024 * 1024
MAX_INFERIOR_WRITE = 64 * 1024
MAX_EXECUTION_JOBS = 32
MAX_LOG_BREAKPOINTS = 64
MAX_LOG_HITS = 1024

_GENERAL_REGISTER_NAMES = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eflags",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags",
    "pc", "sp", "fp", "lr", "cpsr", "xpsr", "ra", "gp", "tp", "hi", "lo",
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2",
    "t3", "t4", "t5", "t6", "t7", "t8", "t9", "s0", "s1", "s2", "s3",
    "s4", "s5", "s6", "s7", "s8", "status", "cause", "badvaddr",
} | {f"r{index}" for index in range(32)} | {f"x{index}" for index in range(31)}


def mi_quote(value: object) -> str:
    """Encode one GDB/MI C-string argument."""

    return json.dumps(str(value), ensure_ascii=True)


def cli_quote(value: object) -> str:
    """Encode one GDB CLI double-quoted argument."""

    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _wire_command(command: str, mode: str) -> str:
    stripped = command.strip()
    if not stripped:
        raise GdbMcpError("command must not be empty", code="invalid_argument")
    if "\n" in stripped or "\r" in stripped:
        raise GdbMcpError(
            "one command per request; embedded newlines are not allowed",
            code="invalid_argument",
        )
    if re.match(r"^\d+-", stripped):
        raise GdbMcpError(
            "MI tokens are owned by the session and must not be supplied",
            code="invalid_argument",
        )
    if mode not in {"auto", "mi", "console"}:
        raise GdbMcpError("mode must be auto, mi, or console", code="invalid_argument")
    is_mi = stripped.startswith("-") if mode == "auto" else mode == "mi"
    if is_mi:
        if not stripped.startswith("-"):
            raise GdbMcpError(
                "MI commands must begin with '-'", code="invalid_argument"
            )
        return stripped
    return f"-interpreter-exec console {mi_quote(stripped)}"


@dataclass
class _PendingCommand:
    token: int
    command: str
    started: float
    event_cursor_start: int = 0
    result: dict[str, Any] | None = None
    error: BaseException | None = None
    console: list[str] = field(default_factory=list)
    target: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    notifications: list[dict[str, Any]] = field(default_factory=list)
    notification_count: int = 0
    notification_summary: dict[str, int] = field(default_factory=dict)
    output_chars: int = 0
    output_truncated: bool = False
    done: threading.Event = field(default_factory=threading.Event)

    def add_stream(self, record_type: str, payload: str) -> None:
        if self.output_chars >= MAX_COMMAND_OUTPUT:
            self.output_truncated = True
            return
        remaining = MAX_COMMAND_OUTPUT - self.output_chars
        kept = payload[:remaining]
        if len(kept) < len(payload):
            self.output_truncated = True
        self.output_chars += len(kept)
        getattr(self, record_type).append(kept)

    def add_notification(self, record: dict[str, Any]) -> None:
        self.notification_count += 1
        key = f"{record.get('type', 'unknown')}:{record.get('message') or 'unknown'}"
        self.notification_summary[key] = self.notification_summary.get(key, 0) + 1
        if len(self.notifications) < MAX_NOTIFICATIONS:
            self.notifications.append(
                bounded_value(record, max_string=MAX_EVENT_STRING, max_items=256)
            )


@dataclass
class _InferiorRecord:
    group_id: str
    inferior_id: int | None = None
    pid: int | None = None
    state: str = "added"
    executable: str | None = None
    exit_code: str | None = None
    threads: set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    exec_count: int = 0
    last_stop: dict[str, Any] | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "inferior_id": self.inferior_id,
            "pid": self.pid,
            "state": self.state,
            "executable": self.executable,
            "exit_code": self.exit_code,
            "threads": sorted(self.threads, key=_numeric_sort_key),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "exec_count": self.exec_count,
            "last_stop": bounded_value(self.last_stop),
        }


@dataclass
class _ExecutionJob:
    job_id: str
    action: str
    command: str
    baseline_stop_id: int
    start_io_cursor: int
    timeout_sec: float
    created_at: float = field(default_factory=time.time)
    state: JobState = "starting"
    revision: int = 1
    command_reply: CommandReply | None = None
    error: dict[str, Any] | None = None
    completed_at: float | None = None
    stop_id: int | None = None
    end_io_cursor: int | None = None
    cancel_requested: bool = False
    kind: str = "execution"
    stop_signals: tuple[str, ...] = ()
    collect: tuple[str, ...] = ()
    evidence: dict[str, Any] | None = None
    restore_signal_commands: tuple[str, ...] = ()
    signal_policy_restored: bool = True

    @property
    def terminal(self) -> bool:
        return self.state in {
            "stopped",
            "exited",
            "cancelled",
            "timed_out",
            "failed",
            "crashed",
            "unexpected_stop",
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "action": self.action,
            "command": self.command,
            "state": self.state,
            "revision": self.revision,
            "baseline_stop_id": self.baseline_stop_id,
            "stop_id": self.stop_id,
            "start_io_cursor": self.start_io_cursor,
            "end_io_cursor": self.end_io_cursor,
            "timeout_sec": self.timeout_sec,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "command_reply": bounded_value(self.command_reply),
            "error": bounded_value(self.error),
            "cancel_requested": self.cancel_requested,
            "kind": self.kind,
            "stop_signals": list(self.stop_signals),
            "collect": list(self.collect),
            "evidence": bounded_value(self.evidence),
            "signal_policy_restored": self.signal_policy_restored,
        }


@dataclass
class _LogBreakpoint:
    log_id: str
    breakpoint_number: str
    location: str
    expressions: tuple[str, ...]
    condition: str
    hit_limit: int
    backtrace_depth: int
    addresses: tuple[int, ...] = ()
    created_at: float = field(default_factory=time.time)
    enabled: bool = True
    hit_count: int = 0
    cursor: int = 0
    hits: deque[dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=MAX_LOG_HITS)
    )
    last_error: dict[str, Any] | None = None

    def snapshot(self) -> dict[str, Any]:
        return {
            "log_id": self.log_id,
            "breakpoint_number": self.breakpoint_number,
            "location": self.location,
            "expressions": list(self.expressions),
            "condition": self.condition,
            "limit": self.hit_limit,
            "backtrace_depth": self.backtrace_depth,
            "addresses": [hex(address) for address in self.addresses],
            "enabled": self.enabled,
            "hit_count": self.hit_count,
            "cursor": self.cursor,
            "retained_hits": len(self.hits),
            "retention_limit": MAX_LOG_HITS,
            "created_at": self.created_at,
            "last_error": bounded_value(self.last_error),
        }


def _numeric_sort_key(value: str) -> tuple[int, str]:
    try:
        return (int(value), value)
    except ValueError:
        return (2**31 - 1, value)


def _inferior_number(group_id: str) -> int | None:
    match = re.fullmatch(r"i(\d+)", group_id)
    return int(match.group(1)) if match else None


def _breakpoint_rows(reply: dict[str, Any]) -> list[dict[str, Any]]:
    payload = reply.get("payload")
    if not isinstance(payload, dict):
        return []
    breakpoint = payload.get("bkpt")
    if isinstance(breakpoint, dict):
        return [breakpoint]
    table = payload.get("BreakpointTable")
    body = table.get("body") if isinstance(table, dict) else None
    return [item for item in body or [] if isinstance(item, dict)]


def _breakpoint_addresses(breakpoint: dict[str, Any]) -> set[int]:
    addresses: set[int] = set()
    candidates = [breakpoint]
    locations = breakpoint.get("locations")
    if isinstance(locations, list):
        candidates.extend(item for item in locations if isinstance(item, dict))
    for item in candidates:
        raw = item.get("addr")
        if isinstance(raw, str) and re.fullmatch(r"0x[0-9a-fA-F]+", raw):
            addresses.add(int(raw, 16))
    return addresses


def _breakpoint_location(breakpoint: dict[str, Any]) -> str | None:
    value = breakpoint.get("original-location")
    return value.strip() if isinstance(value, str) else None


class GdbSession:
    """One GDB process, one MI reader, and one serialized command stream."""

    def __init__(
        self,
        controller: GdbController,
        session_id: str,
        *,
        gdb_path: str = "gdb",
        inferior_args: list[str] | None = None,
        inferior_tty: bool = False,
    ) -> None:
        self.controller = controller
        self.session_id = session_id
        self.gdb_path = gdb_path
        self.inferior_args = list(inferior_args or [])
        self.binary: str | None = None
        self.sysroot: str | None = None
        self.debug_directories: list[str] = ["/usr/lib/debug"]
        self.source_substitutions: list[dict[str, str]] = []
        self.debuginfod_enabled = False
        self.pid: int | None = None
        self.target_kind: TargetKind = "none"
        self.run_state: RunState = "idle"
        self.stop_id = 0
        self.last_stop: dict[str, Any] | None = None
        self.last_command: str | None = None
        self.selected_thread: int | None = None
        self.selected_frame = 0
        self.created_at = time.time()
        self.gdb_version: str | None = None
        self.architecture: str | None = None
        self.endianness: str | None = None
        self.pointer_width: int | None = None
        self.thread_group: str | None = None
        self.exit_code: str | None = None
        self.last_error: dict[str, Any] | None = None
        self.register_names: list[str] | None = None
        self.inferior_tty_enabled = bool(inferior_tty)
        self.inferior_tty_path: str | None = None
        self.selected_inferior: int | None = None
        self.fork_policy: dict[str, Any] = {
            "follow": "parent",
            "detach_on_fork": True,
            "schedule_multiple": False,
        }

        self.command_lock = threading.RLock()
        self.condition = threading.Condition(threading.RLock())
        self._pending: dict[int, _PendingCommand] = {}
        self._active_pending: _PendingCommand | None = None
        self._next_token = 0
        self._event_cursor = 0
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._outputs: OrderedDict[int, str] = OrderedDict()
        self._inferiors: OrderedDict[str, _InferiorRecord] = OrderedDict()
        self._thread_to_group: dict[str, str] = {}
        self._execution_jobs: OrderedDict[str, _ExecutionJob] = OrderedDict()
        self._next_job_id = 0
        self._log_breakpoints: OrderedDict[str, _LogBreakpoint] = OrderedDict()
        self._breakpoint_logs: dict[str, str] = {}
        self._next_log_id = 0
        self._log_actions: deque[tuple[str, dict[str, Any]]] = deque()
        self._action_active: str | None = None
        self._interrupt_after_action = False
        self._capabilities: dict[str, Any] | None = None
        self._capabilities_at: float | None = None
        self._temporary_directories: list[str] = []
        self._adapter_processes: list[Any] = []
        self._closing = threading.Event()
        self._reader_error: BaseException | None = None
        self._pty_master: int | None = None
        self._pty_slave: int | None = None
        self._io_cursor = 0
        self._io_base_cursor = 0
        self._io_buffer = bytearray()
        self._io_reader: threading.Thread | None = None
        self._reader = threading.Thread(
            target=self._reader_main,
            name=f"pygdbmi-reader-{session_id}",
            daemon=True,
        )
        self._action_worker = threading.Thread(
            target=self._log_action_main,
            name=f"pygdbmi-actions-{session_id}",
            daemon=True,
        )
        self._reader.start()
        self._action_worker.start()

    # -- lifecycle -------------------------------------------------------

    def initialize(self, *, working_directory: str = "") -> None:
        for command in (
            "-gdb-set pagination off",
            "-gdb-set confirm off",
            "-gdb-set height 0",
            "-gdb-set width 0",
            "-gdb-set mi-async on",
            "-enable-pretty-printing",
        ):
            self.execute(command, timeout_sec=5.0)
        if self.inferior_tty_enabled:
            self._open_inferior_tty()
            self.execute(
                f"-inferior-tty-set {mi_quote(self.inferior_tty_path)}",
                timeout_sec=5.0,
            )
        if working_directory:
            self.execute(
                f"-environment-cd {mi_quote(Path(working_directory).expanduser().resolve())}",
                timeout_sec=5.0,
            )
        version = self.execute("-gdb-version", timeout_sec=5.0)
        first = version["output"].splitlines()
        self.gdb_version = first[0] if first else None
        if self.inferior_args:
            self.set_inferior_args(self.inferior_args)

    def close(self, policy: str = "auto") -> dict[str, Any]:
        if self._closing.is_set():
            return {"closed": True, "already_closed": True, "policy": policy}
        cleanup = self._cleanup_target(policy)
        self._closing.set()
        with self.condition:
            for job in self._execution_jobs.values():
                if not job.terminal:
                    self._finish_job(
                        job,
                        "cancelled",
                        error={"code": "session_closed", "message": "session closed"},
                    )
            self.condition.notify_all()
        try:
            self.controller.exit()
        except Exception as exc:  # noqa: BLE001 - best-effort third-party teardown
            cleanup.setdefault("errors", []).append(f"exit: {exc}")
        self._close_inferior_tty()
        self._reader.join(timeout=2.0)
        self._action_worker.join(timeout=2.0)
        if self._io_reader is not None:
            self._io_reader.join(timeout=2.0)
        for directory in self._temporary_directories:
            shutil.rmtree(directory, ignore_errors=True)
        self._temporary_directories.clear()
        for process in self._adapter_processes:
            try:
                process.terminate()
                process.wait(timeout=2.0)
            except Exception:  # noqa: BLE001 - external adapter teardown is best effort
                try:
                    process.kill()
                except Exception:
                    pass
        self._adapter_processes.clear()
        with self.condition:
            for pending in self._pending.values():
                pending.error = RuntimeError("session closed")
                pending.done.set()
            self.condition.notify_all()
        cleanup["closed"] = True
        return cleanup

    def _open_inferior_tty(self) -> None:
        if self._pty_master is not None:
            return
        try:
            master, slave = pty.openpty()
            os.set_blocking(master, False)
            self._pty_master = master
            self._pty_slave = slave
            self.inferior_tty_path = os.ttyname(slave)
        except OSError as exc:
            raise GdbMcpError(
                f"could not allocate inferior PTY: {exc}",
                code="pty_unavailable",
            ) from exc
        self._io_reader = threading.Thread(
            target=self._io_reader_main,
            name=f"pygdbmi-inferior-io-{self.session_id}",
            daemon=True,
        )
        self._io_reader.start()

    def _close_inferior_tty(self) -> None:
        for descriptor in (self._pty_master, self._pty_slave):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self._pty_master = None
        self._pty_slave = None

    def _io_reader_main(self) -> None:
        while not self._closing.is_set():
            descriptor = self._pty_master
            if descriptor is None:
                return
            try:
                readable, _, _ = select.select([descriptor], [], [], 0.1)
                if not readable:
                    continue
                data = os.read(descriptor, 64 * 1024)
                if data:
                    self._append_inferior_output(data)
            except OSError as exc:
                if self._closing.is_set() or exc.errno in {errno.EBADF}:
                    return
                if exc.errno == errno.EIO:
                    time.sleep(0.01)
                    continue
                with self.condition:
                    self.last_error = {
                        "code": "pty_read_failed",
                        "message": str(exc)[:2048],
                    }
                return

    def _append_inferior_output(self, data: bytes) -> None:
        with self.condition:
            self._io_buffer.extend(data)
            self._io_cursor += len(data)
            if len(self._io_buffer) > MAX_INFERIOR_IO:
                excess = len(self._io_buffer) - MAX_INFERIOR_IO
                del self._io_buffer[:excess]
                self._io_base_cursor += excess
            self.condition.notify_all()

    def _cleanup_target(self, policy: str) -> dict[str, Any]:
        allowed = {"auto", "kill", "detach", "disconnect", "quit"}
        if policy not in allowed:
            raise GdbMcpError(
                f"policy must be one of {sorted(allowed)}", code="invalid_argument"
            )
        selected = policy
        if selected == "auto":
            selected = {
                "local": (
                    "kill"
                    if self.pid is not None and self.run_state in {"running", "stopped"}
                    else "quit"
                ),
                "attached": "detach",
                "remote": "disconnect",
                "core": "quit",
                "none": "quit",
            }[self.target_kind]
        result: dict[str, Any] = {
            "requested_policy": policy,
            "applied_policy": selected,
            "target_kind": self.target_kind,
            "errors": [],
            "inferiors": [
                inferior.inferior_id
                for inferior in self._active_inferiors()
                if inferior.inferior_id is not None
            ],
        }
        command = {
            "kill": "kill",
            "detach": "-target-detach",
            "disconnect": "-target-disconnect",
            "quit": None,
        }[selected]
        if selected == "kill" and result["inferiors"]:
            command = "kill inferiors " + " ".join(
                str(inferior_id) for inferior_id in result["inferiors"]
            )
        if command is not None and self.target_kind != "none":
            try:
                self.execute(command, timeout_sec=5.0)
            except GdbMcpError as exc:
                result["errors"].append(f"{selected}: {exc}")
        return result

    # -- command dispatcher ---------------------------------------------

    def execute(
        self,
        command: str,
        *,
        timeout_sec: float = 30.0,
        mode: str = "auto",
        output_page_chars: int = DEFAULT_OUTPUT_PAGE,
    ) -> CommandReply:
        if isinstance(timeout_sec, bool) or not 0.05 <= float(timeout_sec) <= 86_400:
            raise GdbMcpError(
                "timeout_sec must be between 0.05 and 86400",
                code="invalid_argument",
            )
        if not 256 <= int(output_page_chars) <= MAX_OUTPUT_PAGE:
            raise GdbMcpError(
                f"output_page_chars must be between 256 and {MAX_OUTPUT_PAGE}",
                code="invalid_argument",
            )
        wire = _wire_command(command, mode)
        with self.command_lock:
            self._require_reader()
            with self.condition:
                self._next_token += 1
                token = self._next_token
                pending = _PendingCommand(
                    token, command, time.monotonic(), self._event_cursor
                )
                self._pending[token] = pending
                self._active_pending = pending
                self.last_command = command
            try:
                self.controller.write(
                    f"{token}{wire}",
                    timeout_sec=min(float(timeout_sec), 5.0),
                    read_response=False,
                )
            except Exception as exc:
                self._discard_pending(pending)
                raise GdbMcpError(
                    f"failed to write command to GDB: {exc}",
                    code="gdb_unreachable",
                    retryable=True,
                ) from exc

            if not pending.done.wait(float(timeout_sec)):
                self._discard_pending(pending)
                with self.condition:
                    self.run_state = "indeterminate"
                    self.last_error = {
                        "code": "timeout",
                        "message": f"GDB command timed out after {float(timeout_sec):g}s",
                    }
                    self.condition.notify_all()
                raise GdbMcpError(
                    f"GDB command timed out after {float(timeout_sec):g}s",
                    code="timeout",
                    retryable=True,
                    details={"command": command[:256], "token": token},
                    recovery=["Call gdb_interrupt, then inspect gdb_session_status."],
                )
            self._discard_pending(pending)
            if pending.error is not None:
                raise GdbMcpError(
                    f"GDB reader failed: {pending.error}",
                    code="gdb_unreachable",
                    retryable=True,
                    recovery=["Stop and recreate the GDB session."],
                ) from pending.error
            if pending.result is None:
                raise GdbMcpError(
                    "GDB command completed without a result record",
                    code="invalid_response",
                    retryable=True,
                )

            output = "".join(pending.console + pending.target + pending.log)
            if pending.output_truncated:
                output += "...<truncated>"
            self._store_output(token, output)
            result_class = str(pending.result.get("message") or "")
            payload = bounded_value(pending.result.get("payload"), max_items=2048)
            reply: CommandReply = {
                "command_id": token,
                "result_class": result_class,
                "payload": payload,
                "output": output[: int(output_page_chars)],
                "output_chars": len(output),
                "next_offset": (
                    int(output_page_chars)
                    if len(output) > int(output_page_chars)
                    else None
                ),
                "truncated": pending.output_truncated
                or len(output) > int(output_page_chars),
                "notifications": pending.notifications,
                "notification_count": pending.notification_count,
                "notification_summary": dict(pending.notification_summary),
                "event_cursor_start": pending.event_cursor_start,
                "event_cursor_end": self._event_cursor,
                "elapsed_ms": round((time.monotonic() - pending.started) * 1000, 3),
            }
            if result_class == "error":
                message = (
                    payload.get("msg") if isinstance(payload, dict) else None
                ) or "GDB command failed"
                self.last_error = {"code": "gdb_error", "message": str(message)[:2048]}
                raise GdbCommandError(
                    message,
                    code="gdb_error",
                    details={"command": command[:256], "reply": reply},
                )
            self.last_error = None
            return reply

    def _discard_pending(self, pending: _PendingCommand) -> None:
        with self.condition:
            self._pending.pop(pending.token, None)
            if self._active_pending is pending:
                self._active_pending = None

    def _require_reader(self) -> None:
        if self._closing.is_set():
            raise GdbMcpError("GDB session is closed", code="no_session")
        if self._reader_error is not None:
            raise GdbMcpError(
                f"GDB reader failed: {self._reader_error}",
                code="gdb_unreachable",
                retryable=True,
            )

    def _reader_main(self) -> None:
        try:
            while not self._closing.is_set():
                records = self.controller.get_gdb_response(
                    timeout_sec=0.1,
                    raise_error_on_timeout=False,
                )
                for record in records:
                    self._route_record(record)
        except Exception as exc:  # noqa: BLE001 - reader failure must wake waiters
            if not self._closing.is_set():
                with self.condition:
                    self._reader_error = exc
                    self.run_state = "indeterminate"
                    self.last_error = {
                        "code": "gdb_unreachable",
                        "message": str(exc)[:2048],
                    }
                    for pending in self._pending.values():
                        pending.error = exc
                        pending.done.set()
                    self.condition.notify_all()

    def _route_record(self, raw: dict[str, Any]) -> None:
        record = bounded_value(raw, max_string=MAX_EVENT_STRING, max_items=512)
        record_type = record.get("type")
        message = record.get("message")
        token = record.get("token")
        payload = record.get("payload")
        with self.condition:
            pending = self._pending.get(token) if isinstance(token, int) else None
            if pending is None:
                pending = self._active_pending

            if (
                pending is not None
                and record_type in {"console", "target", "log"}
                and isinstance(payload, str)
            ):
                pending.add_stream(record_type, payload)
            if pending is not None and record_type in {"exec", "notify", "status"}:
                pending.add_notification(record)
            if record_type == "result" and isinstance(token, int):
                owner = self._pending.get(token)
                if owner is not None:
                    owner.result = record
                    if message == "running":
                        self.run_state = "running"
                        self.last_stop = None
                    owner.done.set()

            managed_log_id = self._managed_log_id(record_type, message, payload)
            if record_type in {"exec", "notify", "status", "target", "log"}:
                self._event_cursor += 1
                event = {
                    "cursor": self._event_cursor,
                    "received_at": time.time(),
                    "record": record,
                }
                if managed_log_id is not None:
                    event["managed_action"] = {
                        "kind": "log_breakpoint",
                        "log_id": managed_log_id,
                    }
                self._events.append(event)
            if managed_log_id is not None:
                self._log_actions.append((managed_log_id, dict(payload)))
            else:
                self._update_state(record_type, message, payload)
            self.condition.notify_all()

    def _managed_log_id(
        self, record_type: Any, message: Any, payload: Any
    ) -> str | None:
        if record_type not in {"exec", "notify"} or message != "stopped":
            return None
        if not isinstance(payload, dict) or payload.get("reason") != "breakpoint-hit":
            return None
        number = str(payload.get("bkptno") or "")
        if not number:
            return None
        log_id = self._breakpoint_logs.get(number)
        if log_id is None and "." in number:
            log_id = self._breakpoint_logs.get(number.split(".", 1)[0])
        trace = self._log_breakpoints.get(log_id or "")
        return log_id if trace is not None and trace.enabled else None

    def _append_internal_event(self, message: str, payload: dict[str, Any]) -> None:
        self._event_cursor += 1
        self._events.append(
            {
                "cursor": self._event_cursor,
                "received_at": time.time(),
                "record": {
                    "type": "status",
                    "message": message,
                    "payload": bounded_value(payload),
                    "token": None,
                },
            }
        )

    def _log_action_main(self) -> None:
        while not self._closing.is_set():
            with self.condition:
                while not self._log_actions and not self._closing.is_set():
                    self.condition.wait(0.25)
                if self._closing.is_set():
                    return
                log_id, stop = self._log_actions.popleft()
                self._action_active = log_id
            try:
                try:
                    self._process_log_hit(log_id, stop)
                except Exception as exc:  # noqa: BLE001 - keep action worker alive
                    with self.condition:
                        trace = self._log_breakpoints.get(log_id)
                        if trace is not None:
                            trace.last_error = {
                                "code": "action_worker_failed",
                                "message": str(exc)[:2048],
                                "exception_type": type(exc).__name__,
                            }
                    self._publish_failed_action_stop(stop, str(exc))
            finally:
                with self.condition:
                    self._action_active = None
                    self.condition.notify_all()

    def _process_log_hit(self, log_id: str, stop: dict[str, Any]) -> None:
        with self.command_lock:
            with self.condition:
                trace = self._log_breakpoints.get(log_id)
            if trace is None or not trace.enabled:
                self._publish_failed_action_stop(
                    stop, "managed logging breakpoint disappeared before collection"
                )
                return

            values: dict[str, Any] = {}
            errors: dict[str, dict[str, str]] = {}
            for expression in trace.expressions:
                try:
                    reply = self.execute(
                        f"-data-evaluate-expression {mi_quote(expression)}",
                        timeout_sec=10.0,
                    )
                    payload = reply.get("payload")
                    values[expression] = (
                        payload.get("value") if isinstance(payload, dict) else payload
                    )
                except GdbMcpError as exc:
                    values[expression] = None
                    errors[expression] = {"code": exc.code, "message": exc.message}

            backtrace: list[Any] = []
            if trace.backtrace_depth:
                try:
                    reply = self.execute(
                        f"-stack-list-frames 0 {trace.backtrace_depth - 1}",
                        timeout_sec=15.0,
                    )
                    payload = reply.get("payload")
                    if isinstance(payload, dict) and isinstance(payload.get("stack"), list):
                        backtrace = payload["stack"][: trace.backtrace_depth]
                except GdbMcpError as exc:
                    errors["backtrace"] = {"code": exc.code, "message": exc.message}

            frame = stop.get("frame") if isinstance(stop.get("frame"), dict) else {}
            with self.condition:
                current = self._log_breakpoints.get(log_id)
                if current is None:
                    self._publish_failed_action_stop(
                        stop, "logging breakpoint was removed during collection"
                    )
                    return
                current.hit_count += 1
                current.cursor += 1
                hit = {
                    "cursor": current.cursor,
                    "hit": current.hit_count,
                    "stop_id": None,
                    "address": frame.get("addr") or stop.get("address"),
                    "thread_id": stop.get("thread-id"),
                    "inferior": stop.get("thread-group") or stop.get("group-id"),
                    "expressions": bounded_value(values),
                    "backtrace": bounded_value(backtrace),
                    "errors": bounded_value(errors),
                    "timestamp": time.time(),
                }
                current.hits.append(hit)
                reached_limit = current.hit_count >= current.hit_limit

            try:
                if reached_limit:
                    self.execute(
                        f"-break-disable {trace.breakpoint_number}", timeout_sec=5.0
                    )
                    with self.condition:
                        trace.enabled = False
                with self.condition:
                    interrupt_requested = self._interrupt_after_action
                if interrupt_requested:
                    self._publish_interrupted_action_stop(stop, log_id)
                    return
                reply = self.execute("-exec-continue", timeout_sec=30.0)
                with self.condition:
                    self._append_internal_event(
                        "log-breakpoint-hit",
                        {
                            "log_id": log_id,
                            "hit": hit["hit"],
                            "cursor": hit["cursor"],
                            "auto_continued": True,
                            "disabled": reached_limit,
                            "command_id": reply.get("command_id"),
                        },
                    )
                    self.condition.notify_all()
            except GdbMcpError as exc:
                with self.condition:
                    trace.last_error = {"code": exc.code, "message": exc.message}
                self._publish_failed_action_stop(stop, exc.message)

    def _publish_failed_action_stop(self, stop: dict[str, Any], message: str) -> None:
        with self.condition:
            visible = {**stop, "managed-action-error": message[:2048]}
            self._update_state("exec", "stopped", visible)
            self._append_internal_event(
                "log-breakpoint-error", {"stop_id": self.stop_id, "message": message}
            )
            self.condition.notify_all()

    def _publish_interrupted_action_stop(
        self, stop: dict[str, Any], log_id: str
    ) -> None:
        with self.condition:
            visible = {**stop, "managed-action-interrupted": True}
            self._update_state("exec", "stopped", visible)
            self._append_internal_event(
                "log-breakpoint-interrupted",
                {"log_id": log_id, "stop_id": self.stop_id},
            )
            self.condition.notify_all()

    def _ensure_inferior(self, group_id: str) -> _InferiorRecord:
        inferior = self._inferiors.get(group_id)
        if inferior is None:
            inferior = _InferiorRecord(
                group_id=group_id,
                inferior_id=_inferior_number(group_id),
            )
            self._inferiors[group_id] = inferior
        inferior.updated_at = time.time()
        return inferior

    def _group_from_payload(self, payload: dict[str, Any]) -> str | None:
        direct = payload.get("thread-group") or payload.get("group-id")
        if direct is not None:
            return str(direct)
        thread_id = payload.get("thread-id") or payload.get("id")
        return (
            self._thread_to_group.get(str(thread_id)) if thread_id is not None else None
        )

    def _active_inferiors(self) -> list[_InferiorRecord]:
        return [
            inferior
            for inferior in self._inferiors.values()
            if inferior.state in {"running", "stopped", "started"}
        ]

    def _update_state(self, record_type: Any, message: Any, payload: Any) -> None:
        data = payload if isinstance(payload, dict) else {}

        if record_type == "notify" and message == "thread-group-added":
            group_id = str(data.get("id") or "")
            if group_id:
                self._ensure_inferior(group_id).state = "added"
                if self.thread_group is None:
                    self.thread_group = group_id
                    self.selected_inferior = _inferior_number(group_id)
            return

        if record_type == "notify" and message == "thread-group-started":
            group_id = str(data.get("id") or self.thread_group or "")
            if group_id:
                inferior = self._ensure_inferior(group_id)
                inferior.state = "started"
                raw_pid = data.get("pid")
                try:
                    inferior.pid = int(raw_pid) if raw_pid is not None else inferior.pid
                except (TypeError, ValueError):
                    pass
                self.thread_group = group_id
                self.selected_inferior = inferior.inferior_id
                self.pid = inferior.pid
            return

        if record_type == "notify" and message == "thread-group-exited":
            group_id = str(data.get("id") or self.thread_group or "")
            if group_id:
                inferior = self._ensure_inferior(group_id)
                inferior.state = "exited"
                code = data.get("exit-code")
                inferior.exit_code = (
                    str(code) if code is not None else inferior.exit_code
                )
                if group_id == self.thread_group:
                    self.exit_code = inferior.exit_code
            if not self._active_inferiors():
                self.run_state = "exited"
            return

        if record_type == "notify" and message == "thread-group-removed":
            group_id = str(data.get("id") or "")
            if group_id:
                self._ensure_inferior(group_id).state = "removed"
            return

        if record_type == "notify" and message == "thread-created":
            thread_id = str(data.get("id") or "")
            group_id = str(data.get("group-id") or "")
            if thread_id and group_id:
                self._thread_to_group[thread_id] = group_id
                self._ensure_inferior(group_id).threads.add(thread_id)
            return

        if record_type == "notify" and message == "thread-exited":
            thread_id = str(data.get("id") or "")
            group_id = str(
                data.get("group-id") or self._thread_to_group.get(thread_id) or ""
            )
            if group_id:
                self._ensure_inferior(group_id).threads.discard(thread_id)
            self._thread_to_group.pop(thread_id, None)
            return

        if message == "running" and record_type in {"result", "exec", "notify"}:
            self.run_state = "running"
            self.last_stop = None
            group_id = self._group_from_payload(data)
            candidates = (
                [self._ensure_inferior(group_id)]
                if group_id
                else [
                    inferior
                    for inferior in self._inferiors.values()
                    if inferior.state not in {"exited", "removed"}
                ]
            )
            for inferior in candidates:
                inferior.state = "running"
                inferior.updated_at = time.time()
            return

        if message == "stopped" and record_type in {"exec", "notify"}:
            stop = data if isinstance(payload, dict) else {"raw": payload}
            self.last_stop = stop
            self.stop_id += 1
            reason = stop.get("reason")
            group_id = self._group_from_payload(stop) or self.thread_group
            inferior = self._ensure_inferior(group_id) if group_id else None
            exited = isinstance(reason, str) and reason.startswith("exited")
            self.run_state = "stopped"
            if inferior is not None:
                inferior.state = "exited" if exited else "stopped"
                inferior.last_stop = bounded_value(stop)
                if reason in {"exec", "exec-called"}:
                    inferior.exec_count += 1
                    self._capabilities = None
                    self._capabilities_at = None
                    frame = stop.get("frame")
                    if isinstance(frame, dict):
                        executable = frame.get("fullname") or frame.get("file")
                        if executable:
                            inferior.executable = str(executable)
                self.thread_group = inferior.group_id
                self.selected_inferior = inferior.inferior_id
                self.pid = inferior.pid
            if exited and not self._active_inferiors():
                self.run_state = "exited"
            thread_id = stop.get("thread-id")
            try:
                self.selected_thread = int(thread_id) if thread_id is not None else None
            except (TypeError, ValueError):
                self.selected_thread = None
            self.selected_frame = 0
            return

        if (
            record_type == "notify"
            and message == "thread-selected"
            and isinstance(payload, dict)
        ):
            raw_id = payload.get("id")
            try:
                self.selected_thread = (
                    int(raw_id) if raw_id is not None else self.selected_thread
                )
            except (TypeError, ValueError):
                pass
            group_id = self._group_from_payload(data)
            if group_id:
                inferior = self._ensure_inferior(group_id)
                self.thread_group = group_id
                self.selected_inferior = inferior.inferior_id
                self.pid = inferior.pid

    # -- state, events, and output paging --------------------------------

    def status(self) -> SessionSummary:
        with self.condition:
            return {
                "session_id": self.session_id,
                "run_state": self.run_state,
                "stop_id": self.stop_id,
                "last_stop": bounded_value(self.last_stop),
                "binary": self.binary,
                "sysroot": self.sysroot,
                "pid": self.pid,
                "target_kind": self.target_kind,
                "selected_thread": self.selected_thread,
                "selected_frame": self.selected_frame,
                "event_cursor": self._event_cursor,
                "created_at": self.created_at,
                "gdb_version": self.gdb_version,
                "architecture": self.architecture,
                "endianness": self.endianness,
                "pointer_width": self.pointer_width,
                "thread_group": self.thread_group,
                "exit_code": self.exit_code,
                "last_error": bounded_value(self.last_error),
                "inferior_tty": self.inferior_tty_path,
                "inferior_io_cursor": self._io_cursor,
                "inferior_io_base_cursor": self._io_base_cursor,
                "selected_inferior": self.selected_inferior,
                "inferior_count": len(self._inferiors),
                "active_inferior_count": len(self._active_inferiors()),
                "inferiors": [item.snapshot() for item in self._inferiors.values()],
                "fork_policy": dict(self.fork_policy),
                "active_execution_jobs": [
                    job.job_id
                    for job in self._execution_jobs.values()
                    if not job.terminal
                ],
                "capabilities_cached_at": self._capabilities_at,
            }

    def events(
        self,
        *,
        after_cursor: int = 0,
        limit: int = 100,
        wait_timeout: float = 0.0,
    ) -> dict[str, Any]:
        if isinstance(after_cursor, bool) or after_cursor < 0:
            raise GdbMcpError(
                "after_cursor must be non-negative", code="invalid_argument"
            )
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise GdbMcpError(
                "limit must be between 1 and 500", code="invalid_argument"
            )
        if isinstance(wait_timeout, bool) or not 0 <= wait_timeout <= 300:
            raise GdbMcpError(
                "wait_timeout must be between 0 and 300", code="invalid_argument"
            )
        deadline = time.monotonic() + wait_timeout
        with self.condition:
            while not any(item["cursor"] > after_cursor for item in self._events):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.condition.wait(remaining)
            available = [item for item in self._events if item["cursor"] > after_cursor]
            items = available[:limit]
            oldest = self._events[0]["cursor"] if self._events else None
            return {
                "events": items,
                "next_cursor": items[-1]["cursor"] if items else after_cursor,
                "truncated": len(available) > len(items),
                "cursor_gap": bool(oldest is not None and after_cursor < oldest - 1),
            }

    def wait_for_stop(
        self, *, after_stop_id: int, timeout_sec: float
    ) -> dict[str, Any]:
        if isinstance(after_stop_id, bool) or after_stop_id < 0:
            raise GdbMcpError(
                "after_stop_id must be non-negative", code="invalid_argument"
            )
        if isinstance(timeout_sec, bool) or not 0 <= timeout_sec <= 300:
            raise GdbMcpError(
                "timeout_sec must be between 0 and 300", code="invalid_argument"
            )
        deadline = time.monotonic() + timeout_sec
        with self.condition:
            while True:
                if self.run_state == "exited":
                    return {"reason": "exited", "session": self.status()}
                if self.run_state == "stopped" and self.stop_id > after_stop_id:
                    return {"reason": "stopped", "session": self.status()}
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"reason": "timeout", "session": self.status()}
                self.condition.wait(remaining)

    # -- managed breakpoint action traces -------------------------------

    def create_log_breakpoint(
        self,
        location: str,
        *,
        expressions: list[str],
        condition: str = "",
        limit: int = 100,
        backtrace_depth: int = 0,
    ) -> dict[str, Any]:
        if not isinstance(location, str) or not location.strip() or len(location) > 4096:
            raise GdbMcpError(
                "location must be a non-empty string of at most 4096 characters",
                code="invalid_argument",
            )
        if any(char in location for char in "\r\n\x00"):
            raise GdbMcpError("location must be one line", code="invalid_argument")
        if not isinstance(expressions, list) or not 1 <= len(expressions) <= 32:
            raise GdbMcpError(
                "expressions must contain 1 to 32 strings", code="invalid_argument"
            )
        if not all(
            isinstance(item, str)
            and item.strip()
            and len(item) <= 4096
            and not any(char in item for char in "\r\n\x00")
            for item in expressions
        ):
            raise GdbMcpError(
                "each expression must be one non-empty line of at most 4096 characters",
                code="invalid_argument",
            )
        if not isinstance(condition, str) or len(condition) > 4096 or any(
            char in condition for char in "\r\n\x00"
        ):
            raise GdbMcpError(
                "condition must be one line of at most 4096 characters",
                code="invalid_argument",
            )
        if isinstance(limit, bool) or not 1 <= limit <= 100_000:
            raise GdbMcpError(
                "limit must be between 1 and 100000", code="invalid_argument"
            )
        if isinstance(backtrace_depth, bool) or not 0 <= backtrace_depth <= 64:
            raise GdbMcpError(
                "backtrace_depth must be between 0 and 64", code="invalid_argument"
            )
        with self.command_lock:
            with self.condition:
                if len(self._log_breakpoints) >= MAX_LOG_BREAKPOINTS:
                    raise GdbMcpError(
                        "logging breakpoint registry is full",
                        code="log_breakpoints_full",
                    )
            existing = self.execute("-break-list", timeout_sec=10.0)
            command = "-break-insert"
            if condition:
                command += f" -c {mi_quote(condition)}"
            command += f" {mi_quote(location)}"
            reply = self.execute(command, timeout_sec=10.0)
            payload = reply.get("payload")
            breakpoint = payload.get("bkpt") if isinstance(payload, dict) else None
            number = breakpoint.get("number") if isinstance(breakpoint, dict) else None
            if number is None:
                raise GdbMcpError(
                    "GDB created a breakpoint without returning its number",
                    code="invalid_response",
                    details={"reply": bounded_value(reply)},
                )
            addresses = _breakpoint_addresses(breakpoint)
            conflicts = [
                {
                    "number": item.get("number"),
                    "location": _breakpoint_location(item),
                    "addresses": [hex(value) for value in _breakpoint_addresses(item)],
                }
                for item in _breakpoint_rows(existing)
                if _breakpoint_location(item) == location.strip()
                or bool(addresses.intersection(_breakpoint_addresses(item)))
            ]
            if conflicts:
                cleanup_error = None
                try:
                    self.execute(f"-break-delete {number}", timeout_sec=5.0)
                except GdbMcpError as exc:
                    cleanup_error = {"code": exc.code, "message": exc.message}
                raise GdbMcpError(
                    "logging breakpoints cannot share an address with another breakpoint",
                    code="breakpoint_conflict",
                    details={
                        "location": location,
                        "addresses": [hex(value) for value in sorted(addresses)],
                        "conflicts": conflicts,
                        "cleanup_error": cleanup_error,
                    },
                    recovery=[
                        "Delete the collocated breakpoint, or merge expressions into one logging breakpoint."
                    ],
                )
            with self.condition:
                self._next_log_id += 1
                log_id = f"log-{self._next_log_id}"
                trace = _LogBreakpoint(
                    log_id=log_id,
                    breakpoint_number=str(number),
                    location=location,
                    expressions=tuple(expressions),
                    condition=condition,
                    hit_limit=limit,
                    backtrace_depth=backtrace_depth,
                    addresses=tuple(sorted(addresses)),
                )
                self._log_breakpoints[log_id] = trace
                self._breakpoint_logs[str(number)] = log_id
                return {"log": trace.snapshot(), "breakpoint": reply}

    def reject_managed_breakpoint_conflict(
        self, reply: dict[str, Any], location: str
    ) -> None:
        """Remove a new ordinary breakpoint if GDB cannot distinguish it from a logger."""
        rows = _breakpoint_rows(reply)
        addresses = {
            address for item in rows for address in _breakpoint_addresses(item)
        }
        with self.condition:
            conflicts = [
                trace
                for trace in self._log_breakpoints.values()
                if trace.location == location.strip()
                or bool(addresses.intersection(trace.addresses))
            ]
        if not conflicts:
            return
        numbers = [str(item.get("number")) for item in rows if item.get("number")]
        cleanup_errors: list[str] = []
        for number in numbers:
            try:
                self.execute(f"-break-delete {number}", timeout_sec=5.0)
            except GdbMcpError as exc:
                cleanup_errors.append(f"{number}: {exc.code}: {exc.message}")
        raise GdbMcpError(
            "ordinary breakpoints cannot share an address with a managed logging breakpoint",
            code="breakpoint_conflict",
            details={
                "location": location,
                "addresses": [hex(value) for value in sorted(addresses)],
                "log_ids": [trace.log_id for trace in conflicts],
                "cleanup_errors": cleanup_errors,
            },
            recovery=[
                "Delete the logging breakpoint first, or rely on its retained evidence."
            ],
        )

    def read_log_breakpoint(
        self, log_id: str, *, after_cursor: int = 0, limit: int = 50
    ) -> dict[str, Any]:
        if isinstance(after_cursor, bool) or after_cursor < 0:
            raise GdbMcpError(
                "after_cursor must be non-negative", code="invalid_argument"
            )
        if isinstance(limit, bool) or not 1 <= limit <= 500:
            raise GdbMcpError(
                "limit must be between 1 and 500", code="invalid_argument"
            )
        with self.condition:
            trace = self._log_breakpoints.get(log_id)
            if trace is None:
                raise GdbMcpError(
                    f"logging breakpoint {log_id!r} is not retained",
                    code="log_not_found",
                )
            available = [item for item in trace.hits if item["cursor"] > after_cursor]
            items = available[:limit]
            oldest = trace.hits[0]["cursor"] if trace.hits else None
            return {
                "log": trace.snapshot(),
                "hits": bounded_value(items),
                "next_cursor": items[-1]["cursor"] if items else after_cursor,
                "truncated": len(available) > len(items),
                "cursor_gap": bool(oldest is not None and after_cursor < oldest - 1),
                "action_active": self._action_active == log_id,
            }

    def list_log_breakpoints(self) -> dict[str, Any]:
        with self.condition:
            logs = [item.snapshot() for item in self._log_breakpoints.values()]
            return {
                "logs": logs,
                "count": len(logs),
                "active_count": sum(item.enabled for item in self._log_breakpoints.values()),
                "retention_limit": MAX_LOG_BREAKPOINTS,
                "action_active": self._action_active,
            }

    def delete_log_breakpoint(self, log_id: str) -> dict[str, Any]:
        with self.command_lock:
            with self.condition:
                trace = self._log_breakpoints.get(log_id)
                if trace is None:
                    raise GdbMcpError(
                        f"logging breakpoint {log_id!r} is not retained",
                        code="log_not_found",
                    )
                if self._action_active == log_id or any(
                    queued_id == log_id for queued_id, _ in self._log_actions
                ):
                    raise GdbMcpError(
                        "logging breakpoint is processing a hit",
                        code="log_action_active",
                        retryable=True,
                    )
                snapshot = trace.snapshot()
            reply = self.execute(
                f"-break-delete {trace.breakpoint_number}", timeout_sec=5.0
            )
            with self.condition:
                self._log_breakpoints.pop(log_id, None)
                self._breakpoint_logs.pop(trace.breakpoint_number, None)
            return {"deleted": snapshot, "breakpoint": reply}

    def interrupt(self, *, timeout_sec: float = 5.0) -> dict[str, Any]:
        with self.condition:
            before = self.stop_id
            if self.run_state == "stopped":
                return {"already_stopped": True, "session": self.status()}
            # A managed logging stop is intentionally hidden while its action
            # worker owns the inferior.  If an interrupt races that window,
            # make the worker publish the stop instead of auto-continuing it.
            self._interrupt_after_action = True
        method = "mi"
        try:
            try:
                self.execute(
                    "-exec-interrupt --all",
                    timeout_sec=max(0.05, min(timeout_sec, 2.0)),
                )
            except GdbMcpError:
                # Older/non-async GDB builds can reject -exec-interrupt. SIGINT is
                # the recovery path, not the primary control channel.
                method = "sigint"
                try:
                    os.kill(self.controller.gdb_process.pid, signal.SIGINT)
                except (AttributeError, OSError) as exc:
                    raise GdbMcpError(
                        f"could not interrupt GDB: {exc}",
                        code="gdb_unreachable",
                        retryable=True,
                    ) from exc
            result = self.wait_for_stop(after_stop_id=before, timeout_sec=timeout_sec)
            if result["reason"] == "timeout":
                with self.condition:
                    self.run_state = "indeterminate"
                raise GdbMcpError(
                    "interrupt requested but GDB did not publish a stop",
                    code="interrupt_timeout",
                    retryable=True,
                )
            return {"interrupt_sent": True, "method": method, **result}
        finally:
            with self.condition:
                self._interrupt_after_action = False

    # -- retained execution operations ----------------------------------

    def start_execution(
        self,
        action: str,
        *,
        instruction: bool = False,
        location: str = "",
        timeout_sec: float = 0.0,
        kind: str = "execution",
        stop_signals: tuple[str, ...] = (),
        collect: tuple[str, ...] = (),
        restore_signal_commands: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        if not isinstance(action, str):
            raise GdbMcpError("action must be a string", code="invalid_argument")
        if not isinstance(instruction, bool):
            raise GdbMcpError("instruction must be boolean", code="invalid_argument")
        if (
            not isinstance(location, str)
            or len(location) > 4096
            or any(char in location for char in "\r\n\x00")
        ):
            raise GdbMcpError(
                "location must be a single string of at most 4096 characters",
                code="invalid_argument",
            )
        if isinstance(timeout_sec, bool) or not 0 <= timeout_sec <= 86_400:
            raise GdbMcpError(
                "timeout_sec must be between 0 and 86400", code="invalid_argument"
            )
        commands = {
            "run": "-exec-run",
            "continue": "-exec-continue",
            "step": "-exec-step-instruction" if instruction else "-exec-step",
            "next": "-exec-next-instruction" if instruction else "-exec-next",
            "finish": "-exec-finish",
            "until": f"-exec-until {mi_quote(location)}" if location else "",
        }
        if action not in commands:
            raise GdbMcpError(
                "action must be run, continue, step, next, finish, or until",
                code="invalid_argument",
            )
        if action == "until" and not location:
            raise GdbMcpError("until requires location", code="invalid_argument")
        if action != "until" and location:
            raise GdbMcpError(
                "location is only valid for until", code="invalid_argument"
            )
        allowed = {"idle", "stopped", "exited"} if action == "run" else {"stopped"}
        with self.command_lock:
            if self.run_state not in allowed:
                raise GdbMcpError(
                    f"cannot {action} while the session is {self.run_state}",
                    code="invalid_state",
                    details={
                        "run_state": self.run_state,
                        "allowed_states": sorted(allowed),
                    },
                )
            self._prune_execution_jobs()
            with self.condition:
                active = [
                    job.job_id
                    for job in self._execution_jobs.values()
                    if not job.terminal
                ]
                if active:
                    raise GdbMcpError(
                        "an execution operation is already active",
                        code="execution_active",
                        details={"active_jobs": active},
                    )
                self._next_job_id += 1
                job = _ExecutionJob(
                    job_id=f"exec-{self._next_job_id}",
                    action=action,
                    command=commands[action],
                    baseline_stop_id=self.stop_id,
                    start_io_cursor=self._io_cursor,
                    timeout_sec=float(timeout_sec),
                    kind=kind,
                    stop_signals=stop_signals,
                    collect=collect,
                    restore_signal_commands=restore_signal_commands,
                    signal_policy_restored=not bool(restore_signal_commands),
                )
                self._execution_jobs[job.job_id] = job
            try:
                reply = self.execute(job.command, timeout_sec=30.0)
            except GdbMcpError as exc:
                with self.condition:
                    self._finish_job(
                        job,
                        "failed",
                        error={"code": exc.code, "message": exc.message},
                    )
                    self.condition.notify_all()
                raise GdbMcpError(
                    exc.message,
                    code=exc.code,
                    retryable=exc.retryable,
                    details={**exc.details, "job_id": job.job_id},
                    recovery=exc.recovery,
                ) from exc
            with self.condition:
                job.command_reply = reply
                if self.run_state == "exited":
                    self._finish_job(job, "exited")
                elif (
                    self.run_state == "stopped" and self.stop_id > job.baseline_stop_id
                ):
                    if job.kind == "crash":
                        job.state = "collecting"
                        job.revision += 1
                    else:
                        self._finish_job(job, "stopped")
                else:
                    job.state = "running"
                    job.revision += 1
                self.condition.notify_all()
            if not job.terminal:
                threading.Thread(
                    target=self._watch_execution,
                    args=(job.job_id,),
                    name=f"pygdbmi-execution-{self.session_id}-{job.job_id}",
                    daemon=True,
                ).start()
            return job.snapshot()

    def _watch_execution(self, job_id: str) -> None:
        started = time.monotonic()
        collect_crash = False
        restore_timed_out_crash = False
        with self.condition:
            while not self._closing.is_set():
                job = self._execution_jobs.get(job_id)
                if job is None or job.terminal:
                    return
                if job.cancel_requested and self.run_state != "running":
                    self._finish_job(job, "cancelled")
                    self.condition.notify_all()
                    return
                if self.run_state == "exited":
                    self._finish_job(job, "exited")
                    self.condition.notify_all()
                    return
                if self.run_state == "stopped" and self.stop_id > job.baseline_stop_id:
                    if job.kind == "crash":
                        job.state = "collecting"
                        job.revision += 1
                        collect_crash = True
                        self.condition.notify_all()
                        break
                    self._finish_job(job, "stopped")
                    self.condition.notify_all()
                    return
                remaining = None
                if job.timeout_sec:
                    remaining = job.timeout_sec - (time.monotonic() - started)
                    if remaining <= 0:
                        if job.kind == "crash":
                            restore_timed_out_crash = True
                            break
                        self._finish_job(
                            job,
                            "timed_out",
                            error={
                                "code": "execution_timeout",
                                "message": "execution operation timed out; target was not interrupted",
                            },
                        )
                        self.condition.notify_all()
                        return
                self.condition.wait(remaining if remaining is not None else 30.0)
        if restore_timed_out_crash:
            restore_errors = self._restore_crash_signal_policy(job)
            with self.condition:
                current = self._execution_jobs.get(job_id)
                if current is not None and not current.terminal:
                    self._finish_job(
                        current,
                        "timed_out",
                        error={
                            "code": "execution_timeout",
                            "message": "crash watch timed out; target was not interrupted",
                            "restore_errors": restore_errors,
                        },
                    )
                    self.condition.notify_all()
            return
        if collect_crash:
            try:
                self._complete_crash_job(job_id)
            except Exception as exc:  # noqa: BLE001 - retain background worker failure
                with self.condition:
                    job = self._execution_jobs.get(job_id)
                    if job is not None and not job.terminal:
                        self._finish_job(
                            job,
                            "failed",
                            error={
                                "code": "evidence_collection_failed",
                                "message": str(exc)[:2048],
                                "exception_type": type(exc).__name__,
                            },
                        )
                        self.condition.notify_all()

    def start_crash_watch(
        self,
        *,
        signals: list[str],
        collect: list[str],
        timeout_sec: float,
    ) -> dict[str, Any]:
        if not isinstance(signals, list) or not 1 <= len(signals) <= 32:
            raise GdbMcpError(
                "signals must contain 1 to 32 signal names", code="invalid_argument"
            )
        normalized_signals: list[str] = []
        for item in signals:
            if not isinstance(item, str) or not re.fullmatch(r"SIG[A-Z0-9]+", item.upper()):
                raise GdbMcpError(
                    "signals must use names such as SIGSEGV", code="invalid_argument"
                )
            name = item.upper()
            if name not in normalized_signals:
                normalized_signals.append(name)
        normalized_collect = self._validate_crash_collect(collect)
        restore_commands: list[str] = []
        with self.command_lock:
            if self.run_state != "stopped":
                raise GdbMcpError(
                    f"cannot arm a crash watch while the session is {self.run_state}",
                    code="invalid_state",
                    details={
                        "run_state": self.run_state,
                        "allowed_states": ["stopped"],
                    },
                    recovery=["Wait for a stop or interrupt the inferior."],
                )
            try:
                for name in normalized_signals:
                    reply = self.execute(f"info handle {name}", timeout_sec=5.0)
                    policy = self._parse_signal_policy(name, reply.get("output", ""))
                    if policy is None:
                        raise GdbMcpError(
                            f"could not parse GDB handling policy for {name}",
                            code="invalid_response",
                        )
                    stop, should_print, should_pass = policy
                    if not stop:
                        restore_commands.append(
                            "handle "
                            + name
                            + " nostop"
                            + (" print" if should_print else " noprint")
                            + (" pass" if should_pass else " nopass")
                        )
                        self.execute(f"handle {name} stop print pass", timeout_sec=5.0)
                return self.start_execution(
                    "continue",
                    timeout_sec=timeout_sec,
                    kind="crash",
                    stop_signals=tuple(normalized_signals),
                    collect=tuple(normalized_collect),
                    restore_signal_commands=tuple(restore_commands),
                )
            except GdbMcpError:
                for command in restore_commands:
                    try:
                        self.execute(command, timeout_sec=5.0)
                    except GdbMcpError:
                        pass
                raise

    @staticmethod
    def _parse_signal_policy(
        signal_name: str, output: str
    ) -> tuple[bool, bool, bool] | None:
        match = re.search(
            rf"^\s*{re.escape(signal_name)}\s+(Yes|No)\s+(Yes|No)\s+(Yes|No)\b",
            output,
            re.MULTILINE | re.IGNORECASE,
        )
        if not match:
            return None
        return tuple(value.lower() == "yes" for value in match.groups())  # type: ignore[return-value]

    def _restore_crash_signal_policy(self, job: _ExecutionJob) -> list[str]:
        errors: list[str] = []
        if job.signal_policy_restored:
            return errors
        for command in job.restore_signal_commands:
            try:
                self.execute(command, timeout_sec=5.0)
            except GdbMcpError as exc:
                # Some remote targets apply `handle` and then return an error
                # merely because the inferior is running. Trust the observed
                # policy, not that self-contradictory result record.
                match = re.fullmatch(
                    r"handle\s+(SIG[A-Z0-9]+)\s+(stop|nostop)\s+"
                    r"(print|noprint)\s+(pass|nopass)",
                    command,
                )
                verified = False
                verification_error = None
                if match:
                    try:
                        reply = self.execute(
                            f"info handle {match.group(1)}", timeout_sec=5.0
                        )
                        observed = self._parse_signal_policy(
                            match.group(1), reply.get("output", "")
                        )
                        expected = (
                            match.group(2) == "stop",
                            match.group(3) == "print",
                            match.group(4) == "pass",
                        )
                        verified = observed == expected
                    except GdbMcpError as verify_exc:
                        verification_error = (
                            f"; verification failed: {verify_exc.code}: "
                            f"{verify_exc.message}"
                        )
                if not verified:
                    errors.append(
                        f"{command}: {exc.code}: {exc.message}"
                        + (verification_error or "")
                    )
        job.signal_policy_restored = not errors
        return errors

    def _validate_crash_collect(self, collect: list[str]) -> list[str]:
        if not isinstance(collect, list) or not 1 <= len(collect) <= 16:
            raise GdbMcpError(
                "collect must contain 1 to 16 evidence specifications",
                code="invalid_argument",
            )
        normalized: list[str] = []
        total_memory = 0
        for item in collect:
            if not isinstance(item, str) or not item.strip() or len(item) > 4096:
                raise GdbMcpError(
                    "each collect item must be a non-empty string",
                    code="invalid_argument",
                )
            if item in {"backtrace", "registers"}:
                normalized.append(item)
                continue
            if item.startswith("memory:"):
                try:
                    expression, raw_size = item.removeprefix("memory:").rsplit(",", 1)
                    size = int(raw_size, 0)
                except (ValueError, TypeError) as exc:
                    raise GdbMcpError(
                        "memory evidence must be memory:<expression>,<bytes>",
                        code="invalid_argument",
                    ) from exc
                if not expression.strip() or any(char in expression for char in "\r\n\x00"):
                    raise GdbMcpError(
                        "memory expression must be one non-empty line",
                        code="invalid_argument",
                    )
                if not 1 <= size <= 4096:
                    raise GdbMcpError(
                        "each memory evidence range must be 1 to 4096 bytes",
                        code="invalid_argument",
                    )
                total_memory += size
                if total_memory > 16 * 1024:
                    raise GdbMcpError(
                        "total crash memory evidence exceeds 16384 bytes",
                        code="invalid_argument",
                    )
                normalized.append(f"memory:{expression},{size}")
                continue
            raise GdbMcpError(
                "collect items must be backtrace, registers, or memory:<expression>,<bytes>",
                code="invalid_argument",
            )
        return normalized

    def _complete_crash_job(self, job_id: str) -> None:
        with self.command_lock:
            with self.condition:
                job = self._execution_jobs.get(job_id)
                if job is None or job.terminal or job.cancel_requested:
                    return
                stop_id = self.stop_id
                stop = dict(self.last_stop or {})
                signal_name = str(stop.get("signal-name") or "").upper()
                matched = (
                    stop.get("reason") == "signal-received"
                    and signal_name in job.stop_signals
                )
            if not matched:
                restore_errors = self._restore_crash_signal_policy(job)
                with self.condition:
                    current = self._execution_jobs.get(job_id)
                    if current is None or current.terminal:
                        return
                    self._finish_job(
                        current,
                        "unexpected_stop",
                        error={
                            "code": "unexpected_stop",
                            "message": "target stopped for a reason other than a selected crash signal",
                            "stop": bounded_value(stop),
                            "restore_errors": restore_errors,
                        },
                    )
                    self.condition.notify_all()
                    return
            evidence = self._collect_crash_evidence(
                stop_id=stop_id, stop=stop, collect=job.collect
            )
            with self.condition:
                current = self._execution_jobs.get(job_id)
                if current is None or current.terminal:
                    return
            restore_errors = self._restore_crash_signal_policy(current)
            with self.condition:
                current = self._execution_jobs.get(job_id)
                if current is None or current.terminal:
                    return
                if restore_errors:
                    evidence["partial"] = True
                    evidence.setdefault("errors", {})["signal_policy_restore"] = restore_errors
                current.evidence = evidence
                self._finish_job(current, "crashed")
                self._append_internal_event(
                    "crash-captured",
                    {
                        "job_id": job_id,
                        "stop_id": stop_id,
                        "signal": signal_name,
                        "partial": evidence.get("partial", False),
                    },
                )
                self.condition.notify_all()

    def _collect_crash_evidence(
        self, *, stop_id: int, stop: dict[str, Any], collect: tuple[str, ...]
    ) -> dict[str, Any]:
        evidence: dict[str, Any] = {
            "stop_id": stop_id,
            "stop": bounded_value(stop),
            "backtrace": None,
            "registers": None,
            "memory": [],
        }
        errors: dict[str, Any] = {}

        def run(name: str, command: str, timeout: float = 15.0) -> Any:
            try:
                reply = self.execute(command, timeout_sec=timeout)
                if self.stop_id != stop_id or self.run_state != "stopped":
                    raise GdbMcpError(
                        "stop epoch changed while collecting crash evidence",
                        code="stale_stop",
                    )
                return reply.get("payload")
            except GdbMcpError as exc:
                errors[name] = {"code": exc.code, "message": exc.message}
                return None

        if "backtrace" in collect:
            payload = run("backtrace", "-stack-list-frames 0 63")
            evidence["backtrace"] = (
                payload.get("stack", []) if isinstance(payload, dict) else []
            )
        if "registers" in collect:
            if self.register_names is None:
                payload = run("register_names", "-data-list-register-names")
                names = payload.get("register-names", []) if isinstance(payload, dict) else []
                self.register_names = [str(name) for name in names]
            payload = run("registers", "-data-list-register-values x")
            values = payload.get("register-values", []) if isinstance(payload, dict) else []
            registers: dict[str, str] = {}
            for item in values if isinstance(values, list) else []:
                if not isinstance(item, dict):
                    continue
                try:
                    index = int(item["number"])
                    name = self.register_names[index] if self.register_names else str(index)
                except (KeyError, TypeError, ValueError, IndexError):
                    continue
                if name in _GENERAL_REGISTER_NAMES:
                    registers[name] = str(item.get("value", ""))
            evidence["registers"] = registers
        for index, item in enumerate(collect):
            if not item.startswith("memory:"):
                continue
            expression, raw_size = item.removeprefix("memory:").rsplit(",", 1)
            size = int(raw_size)
            payload = run(
                f"memory:{index}",
                f"-data-read-memory-bytes {mi_quote(expression)} {size}",
            )
            evidence["memory"].append(
                {"expression": expression, "bytes": size, "payload": payload}
            )
        evidence["partial"] = bool(errors)
        evidence["errors"] = errors
        evidence["collected_at"] = time.time()
        return bounded_value(evidence)

    def _finish_job(
        self,
        job: _ExecutionJob,
        state: JobState,
        *,
        error: dict[str, Any] | None = None,
    ) -> None:
        job.state = state
        job.error = bounded_value(error) if error else None
        job.completed_at = time.time()
        job.stop_id = self.stop_id
        job.end_io_cursor = self._io_cursor
        job.revision += 1

    def _prune_execution_jobs(self) -> None:
        with self.condition:
            while len(self._execution_jobs) >= MAX_EXECUTION_JOBS:
                removable = next(
                    (
                        job_id
                        for job_id, job in self._execution_jobs.items()
                        if job.terminal
                    ),
                    None,
                )
                if removable is None:
                    raise GdbMcpError(
                        "execution job retention is full",
                        code="execution_jobs_full",
                    )
                self._execution_jobs.pop(removable)

    def execution_status(
        self,
        job_id: str,
        *,
        after_revision: int = 0,
        wait_timeout: float = 0.0,
    ) -> dict[str, Any]:
        if isinstance(after_revision, bool) or after_revision < 0:
            raise GdbMcpError(
                "after_revision must be non-negative", code="invalid_argument"
            )
        if isinstance(wait_timeout, bool) or not 0 <= wait_timeout <= 300:
            raise GdbMcpError(
                "wait_timeout must be between 0 and 300", code="invalid_argument"
            )
        deadline = time.monotonic() + wait_timeout
        with self.condition:
            while True:
                job = self._execution_jobs.get(job_id)
                if job is None:
                    raise GdbMcpError(
                        f"execution job {job_id!r} is not retained",
                        code="execution_not_found",
                    )
                if job.revision > after_revision or job.terminal:
                    return job.snapshot()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return job.snapshot()
                self.condition.wait(remaining)

    def list_executions(self) -> dict[str, Any]:
        with self.condition:
            jobs = [job.snapshot() for job in self._execution_jobs.values()]
            active_count = sum(
                not job.terminal for job in self._execution_jobs.values()
            )
            return {
                "jobs": jobs,
                "count": len(jobs),
                "active_count": active_count,
                "terminal_count": len(jobs) - active_count,
                "retention_limit": MAX_EXECUTION_JOBS,
            }

    def cancel_execution(
        self, job_id: str, *, timeout_sec: float = 5.0
    ) -> dict[str, Any]:
        if isinstance(timeout_sec, bool) or not 0.05 <= timeout_sec <= 300:
            raise GdbMcpError(
                "timeout_sec must be between 0.05 and 300", code="invalid_argument"
            )
        with self.condition:
            job = self._execution_jobs.get(job_id)
            if job is None:
                raise GdbMcpError(
                    f"execution job {job_id!r} is not retained",
                    code="execution_not_found",
                )
            if job.terminal and not (
                job.state == "timed_out" and self.run_state == "running"
            ):
                return {"already_terminal": True, "job": job.snapshot()}
            job.cancel_requested = True
            job.state = "cancelling"
            job.revision += 1
            self.condition.notify_all()
        try:
            interrupt = self.interrupt(timeout_sec=timeout_sec)
        except GdbMcpError as exc:
            # A remote stub can acknowledge -exec-interrupt without ever
            # publishing the asynchronous stop.  Do not leave the retained
            # job permanently wedged in the non-terminal "cancelling" state.
            with self.condition:
                if not job.terminal:
                    self._finish_job(
                        job,
                        "failed",
                        error={
                            "code": "cancel_failed",
                            "message": exc.message,
                            "cause": {
                                "code": exc.code,
                                "retryable": exc.retryable,
                                "details": exc.details,
                            },
                        },
                    )
            restore_errors = (
                self._restore_crash_signal_policy(job)
                if job.kind == "crash"
                else []
            )
            with self.condition:
                if job.error is not None:
                    job.error["restore_errors"] = restore_errors
                snapshot = job.snapshot()
                self.condition.notify_all()
            raise GdbMcpError(
                exc.message,
                code=exc.code,
                retryable=exc.retryable,
                details={
                    **exc.details,
                    "job_id": job_id,
                    "job": snapshot,
                    "restore_errors": restore_errors,
                },
                recovery=exc.recovery,
            ) from exc
        restore_errors = (
            self._restore_crash_signal_policy(job) if job.kind == "crash" else []
        )
        with self.condition:
            if not job.terminal or job.state == "timed_out":
                self._finish_job(job, "cancelled")
            self.condition.notify_all()
            return {
                "already_terminal": False,
                "interrupt": interrupt,
                "restore_errors": restore_errors,
                "job": job.snapshot(),
            }

    # -- inferior topology and target capabilities ----------------------

    def inferiors(self, *, refresh: bool = True) -> dict[str, Any]:
        if not isinstance(refresh, bool):
            raise GdbMcpError("refresh must be boolean", code="invalid_argument")
        reply = None
        if refresh:
            reply = self.execute("-list-thread-groups --recurse 1", timeout_sec=10.0)
            payload = reply.get("payload")
            groups = payload.get("groups", []) if isinstance(payload, dict) else []
            with self.condition:
                for group in groups:
                    if not isinstance(group, dict):
                        continue
                    group_id = str(group.get("id") or "")
                    if not group_id:
                        continue
                    inferior = self._ensure_inferior(group_id)
                    raw_pid = group.get("pid")
                    try:
                        inferior.pid = (
                            int(raw_pid) if raw_pid is not None else inferior.pid
                        )
                    except (TypeError, ValueError):
                        pass
                    executable = group.get("executable")
                    if executable:
                        inferior.executable = str(executable)
                    threads = group.get("threads")
                    if isinstance(threads, list):
                        previous_threads = set(inferior.threads)
                        current_threads: set[str] = set()
                        thread_states: set[str] = set()
                        for thread in threads:
                            if not isinstance(thread, dict) or thread.get("id") is None:
                                continue
                            thread_id = str(thread["id"])
                            current_threads.add(thread_id)
                            self._thread_to_group[thread_id] = group_id
                            if thread.get("state") is not None:
                                thread_states.add(str(thread["state"]))
                        inferior.threads = current_threads
                        for thread_id in previous_threads - current_threads:
                            self._thread_to_group.pop(thread_id, None)
                        if "running" in thread_states:
                            inferior.state = "running"
                        elif thread_states:
                            inferior.state = "stopped"
                    exit_code = group.get("exit-code")
                    if exit_code is not None:
                        inferior.exit_code = str(exit_code)
                        inferior.state = "exited"
                    elif inferior.state == "added" and inferior.pid is not None:
                        inferior.state = (
                            "stopped" if self.run_state == "stopped" else "started"
                        )

                current_thread = (
                    str(payload.get("current-thread-id"))
                    if isinstance(payload, dict)
                    and payload.get("current-thread-id") is not None
                    else None
                )
                current_group = self._thread_to_group.get(current_thread or "")
                if current_group:
                    inferior = self._ensure_inferior(current_group)
                    self.thread_group = current_group
                    self.selected_inferior = inferior.inferior_id
                    self.pid = inferior.pid
                    try:
                        self.selected_thread = (
                            int(current_thread) if current_thread else None
                        )
                    except ValueError:
                        self.selected_thread = None
        with self.condition:
            items = [item.snapshot() for item in self._inferiors.values()]
            return {
                "inferiors": items,
                "count": len(items),
                "active_count": len(self._active_inferiors()),
                "selected_inferior": self.selected_inferior,
                "selected_group": self.thread_group,
                "refresh_reply": reply,
            }

    def select_inferior(self, inferior_id: int) -> dict[str, Any]:
        if isinstance(inferior_id, bool) or inferior_id < 1:
            raise GdbMcpError("inferior_id must be positive", code="invalid_argument")
        reply = self.execute(f"inferior {inferior_id}", timeout_sec=10.0)
        group_id = f"i{inferior_id}"
        with self.condition:
            inferior = self._ensure_inferior(group_id)
            self.selected_inferior = inferior_id
            self.thread_group = group_id
            self.pid = inferior.pid
            self.selected_thread = None
            self.selected_frame = 0
        return {"selected_inferior": inferior_id, "group_id": group_id, "reply": reply}

    def set_fork_policy(
        self,
        *,
        follow: str,
        detach_on_fork: bool,
        schedule_multiple: bool,
    ) -> dict[str, Any]:
        if follow not in {"parent", "child"}:
            raise GdbMcpError("follow must be parent or child", code="invalid_argument")
        if not isinstance(detach_on_fork, bool) or not isinstance(
            schedule_multiple, bool
        ):
            raise GdbMcpError(
                "detach_on_fork and schedule_multiple must be boolean",
                code="invalid_argument",
            )
        with self.command_lock:
            return self._set_fork_policy_locked(
                follow=follow,
                detach_on_fork=detach_on_fork,
                schedule_multiple=schedule_multiple,
            )

    def _set_fork_policy_locked(
        self,
        *,
        follow: str,
        detach_on_fork: bool,
        schedule_multiple: bool,
    ) -> dict[str, Any]:
        requested = {
            "follow": follow,
            "detach_on_fork": detach_on_fork,
            "schedule_multiple": schedule_multiple,
        }
        previous = dict(self.fork_policy)
        settings = [
            ("follow", "follow-fork-mode", follow),
            ("detach_on_fork", "detach-on-fork", "on" if detach_on_fork else "off"),
            (
                "schedule_multiple",
                "schedule-multiple",
                "on" if schedule_multiple else "off",
            ),
        ]
        replies: list[CommandReply] = []
        applied: list[tuple[str, str]] = []
        try:
            for key, setting, value in settings:
                replies.append(
                    self.execute(f"-gdb-set {setting} {value}", timeout_sec=5.0)
                )
                applied.append((key, setting))
        except GdbMcpError as exc:
            rollback_errors: list[str] = []
            for key, setting in reversed(applied):
                old = previous[key]
                old_value = old if key == "follow" else "on" if old else "off"
                try:
                    self.execute(f"-gdb-set {setting} {old_value}", timeout_sec=5.0)
                except GdbMcpError as rollback_exc:
                    rollback_errors.append(f"{setting}: {rollback_exc.message}")
            raise GdbMcpError(
                exc.message,
                code=exc.code,
                retryable=exc.retryable,
                details={
                    **exc.details,
                    "requested_policy": requested,
                    "previous_policy": previous,
                    "applied_before_failure": [key for key, _ in applied],
                    "rollback_errors": rollback_errors,
                },
                recovery=exc.recovery,
            ) from exc
        self.fork_policy = requested
        return {"policy": dict(self.fork_policy), "replies": replies}

    def capabilities(self, *, refresh: bool = False) -> dict[str, Any]:
        if not isinstance(refresh, bool):
            raise GdbMcpError("refresh must be boolean", code="invalid_argument")
        with self.command_lock:
            return self._capabilities_locked(refresh=refresh)

    def _capabilities_locked(self, *, refresh: bool) -> dict[str, Any]:
        with self.condition:
            if self._capabilities is not None and not refresh:
                return {**bounded_value(self._capabilities), "cached": True}
            if self.run_state == "running":
                raise GdbMcpError(
                    "capability refresh is unavailable while the target is running",
                    code="invalid_state",
                    details={"run_state": self.run_state},
                    recovery=["Use the cached manifest or interrupt the inferior."],
                )

        errors: dict[str, str] = {}

        def query(name: str, command: str) -> CommandReply | None:
            try:
                return self.execute(command, timeout_sec=10.0)
            except GdbMcpError as exc:
                errors[name] = f"{exc.code}: {exc.message}"
                return None

        features_reply = query("mi_features", "-list-features")
        target_reply = query("target_features", "-list-target-features")
        osabi_reply = query("osabi", "show osabi")
        non_stop_reply = query("non_stop", "show non-stop")
        mi_commands: dict[str, bool] = {}
        for command in (
            "data-read-memory-bytes",
            "exec-reverse-continue",
            "exec-reverse-next",
            "list-thread-groups",
            "var-update",
        ):
            reply = query(
                f"mi_command:{command}", f"-info-gdb-mi-command {mi_quote(command)}"
            )
            payload = reply.get("payload") if reply else None
            info = payload.get("command") if isinstance(payload, dict) else None
            exists = info.get("exists") if isinstance(info, dict) else None
            mi_commands[command] = str(exists).lower() == "true"

        def payload_list(reply: CommandReply | None, key: str) -> list[str]:
            payload = reply.get("payload") if reply else None
            values = payload.get(key, []) if isinstance(payload, dict) else []
            return (
                sorted(str(value) for value in values)
                if isinstance(values, list)
                else []
            )

        osabi_output = osabi_reply["output"] if osabi_reply else ""
        osabi_matches = re.findall(r'"([^"]+)"', osabi_output)
        non_stop_output = non_stop_reply["output"].lower() if non_stop_reply else ""
        discovered_at = time.time()
        result = {
            "revision": "pygdbmi.capabilities/1",
            "discovered_at": discovered_at,
            "gdb_version": self.gdb_version,
            "architecture": self.architecture,
            "endianness": self.endianness,
            "pointer_width": self.pointer_width,
            "osabi": osabi_matches[-1] if osabi_matches else None,
            "osabi_setting": osabi_matches[0] if osabi_matches else None,
            "mi_features": payload_list(features_reply, "features"),
            "target_features": payload_list(target_reply, "features"),
            "mi_commands": mi_commands,
            "non_stop": "is on" in non_stop_output,
            "inferior_tty": self.inferior_tty_path is not None,
            "async_events": True,
            "adapters": {
                "rr": shutil.which("rr"),
                "objcopy": shutil.which("objcopy"),
            },
            "errors": errors,
        }
        with self.condition:
            self._capabilities = bounded_value(result)
            self._capabilities_at = discovered_at
            return {**bounded_value(result), "cached": False}

    def invalidate_capabilities(self) -> None:
        with self.condition:
            self._capabilities = None
            self._capabilities_at = None

    def _store_output(self, command_id: int, output: str) -> None:
        self._outputs[command_id] = output[:MAX_COMMAND_OUTPUT]
        self._outputs.move_to_end(command_id)
        while len(self._outputs) > MAX_STORED_OUTPUTS:
            self._outputs.popitem(last=False)

    def output_page(self, command_id: int, offset: int, limit: int) -> dict[str, Any]:
        if isinstance(command_id, bool) or command_id < 1:
            raise GdbMcpError("command_id must be positive", code="invalid_argument")
        if isinstance(offset, bool) or offset < 0:
            raise GdbMcpError("offset must be non-negative", code="invalid_argument")
        if isinstance(limit, bool) or not 256 <= limit <= MAX_OUTPUT_PAGE:
            raise GdbMcpError(
                f"limit must be between 256 and {MAX_OUTPUT_PAGE}",
                code="invalid_argument",
            )
        with self.command_lock:
            output = self._outputs.get(command_id)
            if output is None:
                raise GdbMcpError(
                    f"command output {command_id} is not retained",
                    code="output_not_found",
                )
            page = output[offset : offset + limit]
            next_offset = offset + len(page)
            return {
                "command_id": command_id,
                "offset": offset,
                "output": page,
                "next_offset": next_offset if next_offset < len(output) else None,
                "total_chars": len(output),
            }

    def inferior_io(
        self,
        *,
        after_cursor: int = 0,
        limit: int = DEFAULT_OUTPUT_PAGE,
        wait_timeout: float = 0.0,
        encoding: str = "utf-8",
    ) -> dict[str, Any]:
        """Read a bounded page from the session-owned inferior PTY."""
        if self._pty_master is None:
            raise GdbMcpError(
                "this session has no inferior PTY",
                code="pty_unavailable",
                recovery=["Start a session with inferior_tty=true."],
            )
        if isinstance(after_cursor, bool) or after_cursor < 0:
            raise GdbMcpError(
                "after_cursor must be non-negative", code="invalid_argument"
            )
        if isinstance(limit, bool) or not 1 <= limit <= MAX_OUTPUT_PAGE:
            raise GdbMcpError(
                f"limit must be between 1 and {MAX_OUTPUT_PAGE}",
                code="invalid_argument",
            )
        if isinstance(wait_timeout, bool) or not 0 <= wait_timeout <= 300:
            raise GdbMcpError(
                "wait_timeout must be between 0 and 300", code="invalid_argument"
            )
        if encoding not in {"utf-8", "hex", "base64"}:
            raise GdbMcpError(
                "encoding must be utf-8, hex, or base64", code="invalid_argument"
            )
        deadline = time.monotonic() + wait_timeout
        with self.condition:
            while self._io_cursor <= after_cursor:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.condition.wait(remaining)
            cursor_gap = after_cursor < self._io_base_cursor
            start = max(after_cursor, self._io_base_cursor)
            relative = start - self._io_base_cursor
            page = bytes(self._io_buffer[relative : relative + limit])
            next_cursor = start + len(page)
            if encoding == "hex":
                output = page.hex()
            elif encoding == "base64":
                output = base64.b64encode(page).decode("ascii")
            else:
                output = page.decode("utf-8", errors="replace")
            return {
                "encoding": encoding,
                "output": output,
                "bytes": len(page),
                "start_cursor": start,
                "next_cursor": next_cursor,
                "available_cursor": self._io_cursor,
                "truncated": next_cursor < self._io_cursor,
                "cursor_gap": cursor_gap,
            }

    def write_inferior(
        self,
        data: str,
        *,
        encoding: str = "utf-8",
    ) -> dict[str, Any]:
        """Write bounded input to the session-owned inferior PTY."""
        descriptor = self._pty_master
        if descriptor is None:
            raise GdbMcpError(
                "this session has no inferior PTY", code="pty_unavailable"
            )
        try:
            if encoding == "utf-8":
                raw = data.encode("utf-8")
            elif encoding == "hex":
                raw = bytes.fromhex(data)
            elif encoding == "base64":
                raw = base64.b64decode(data, validate=True)
            else:
                raise GdbMcpError(
                    "encoding must be utf-8, hex, or base64",
                    code="invalid_argument",
                )
        except (ValueError, UnicodeError) as exc:
            raise GdbMcpError(
                f"invalid {encoding} inferior input", code="invalid_argument"
            ) from exc
        if not raw or len(raw) > MAX_INFERIOR_WRITE:
            raise GdbMcpError(
                f"inferior input must contain 1 to {MAX_INFERIOR_WRITE} bytes",
                code="invalid_argument",
            )
        written = 0
        try:
            while written < len(raw):
                _, writable, _ = select.select([], [descriptor], [], 1.0)
                if not writable:
                    raise TimeoutError("inferior PTY remained unwritable")
                written += os.write(descriptor, raw[written:])
        except (OSError, TimeoutError) as exc:
            raise GdbMcpError(
                f"could not write inferior input: {exc}",
                code="pty_write_failed",
                retryable=True,
            ) from exc
        return {"bytes_written": written, "encoding": encoding}

    # -- helpers ---------------------------------------------------------

    def set_inferior_args(self, args: list[str]) -> CommandReply:
        command = "-exec-arguments"
        if args:
            command += " " + " ".join(mi_quote(item) for item in args)
        reply = self.execute(command, timeout_sec=5.0)
        self.inferior_args = list(args)
        return reply

    def refresh_target_traits(self) -> None:
        """Best-effort cached target traits; failure never invalidates a load."""
        self.invalidate_capabilities()
        try:
            output = self.execute("show architecture", timeout_sec=5.0)["output"]
            match = re.search(r"currently\s+([^.)]+)", output, re.IGNORECASE)
            if match is None:
                match = re.search(
                    r"architecture\s+is\s+([^\n.]+)", output, re.IGNORECASE
                )
            self.architecture = (
                match.group(1).strip().strip('"')
                if match
                else output.strip()[:256] or None
            )
        except GdbMcpError:
            pass
        try:
            output = self.execute("show endian", timeout_sec=5.0)["output"].lower()
            if "little endian" in output:
                self.endianness = "little"
            elif "big endian" in output:
                self.endianness = "big"
        except GdbMcpError:
            pass
        try:
            reply = self.execute(
                f"-data-evaluate-expression {mi_quote('sizeof(void *)')}",
                timeout_sec=5.0,
            )
            payload = reply.get("payload")
            value = payload.get("value") if isinstance(payload, dict) else None
            self.pointer_width = int(str(value), 0) * 8 if value is not None else None
        except (GdbMcpError, TypeError, ValueError):
            pass

    def set_state(self, state: RunState, *, clear_stop: bool = False) -> None:
        with self.condition:
            self.run_state = state
            if clear_stop:
                self.last_stop = None
            self.condition.notify_all()

    def mark_synthetic_stop(self, payload: dict[str, Any]) -> None:
        with self.condition:
            self.stop_id += 1
            self.last_stop = bounded_value(payload)
            self.run_state = "stopped"
            self.condition.notify_all()


ControllerFactory = Callable[..., GdbController]


class GdbManager:
    def __init__(self, controller_factory: ControllerFactory = GdbController) -> None:
        self.controller_factory = controller_factory
        self.sessions: dict[str, GdbSession] = {}
        self._counter = 0
        self.lock = threading.RLock()

    def create(
        self,
        *,
        gdb_path: str = "gdb",
        gdb_args: list[str] | None = None,
        inferior_args: list[str] | None = None,
        inferior_tty: bool = True,
        working_directory: str = "",
    ) -> str:
        args = list(gdb_args or [])
        conflicting = (
            "--args",
            "--batch",
            "--batch-silent",
            "--command",
            "--core",
            "--interpreter",
            "--pid",
            "-c",
            "-i",
            "-p",
            "-x",
        )
        rejected = [
            arg
            for arg in args
            if any(
                arg == prefix or arg.startswith(prefix + "=") for prefix in conflicting
            )
        ]
        if rejected:
            raise GdbMcpError(
                "gdb_args contains options that conflict with managed MI mode",
                code="invalid_argument",
                details={"rejected": rejected},
            )
        inferior = list(inferior_args or [])
        if len(inferior) > 256 or any(
            len(str(item)) > 4096 or "\x00" in str(item) for item in inferior
        ):
            raise GdbMcpError(
                "inferior_args allows at most 256 items of 4096 characters without NULs",
                code="invalid_argument",
            )
        with self.lock:
            self._counter += 1
            session_id = f"gdb-{self._counter}"
        command = [gdb_path, *args, "--nx", "--quiet", "--interpreter=mi3"]
        try:
            controller = self.controller_factory(command=command)
        except Exception as exc:
            raise GdbMcpError(
                f"could not start GDB at {gdb_path!r}: {exc}",
                code="gdb_start_failed",
                details={"gdb_path": gdb_path},
            ) from exc
        session = GdbSession(
            controller,
            session_id,
            gdb_path=gdb_path,
            inferior_args=inferior,
            inferior_tty=inferior_tty,
        )
        try:
            session.initialize(working_directory=working_directory)
        except BaseException:
            session.close("quit")
            raise
        with self.lock:
            self.sessions[session_id] = session
        return session_id

    def get(self, session_id: str) -> GdbSession:
        with self.lock:
            session = self.sessions.get(session_id)
            active = sorted(self.sessions)
        if session is None:
            raise GdbMcpError(
                f"no GDB session with id {session_id!r}",
                code="no_session",
                details={"active_sessions": active},
                recovery=["Call gdb_start and use the returned session ID."],
            )
        return session

    def destroy(self, session_id: str, *, policy: str = "auto") -> dict[str, Any]:
        with self.lock:
            session = self.sessions.pop(session_id, None)
        if session is None:
            raise GdbMcpError(
                f"no GDB session with id {session_id!r}", code="no_session"
            )
        return session.close(policy)

    def destroy_all(self) -> None:
        with self.lock:
            items = list(self.sessions.items())
            self.sessions.clear()
        for _, session in items:
            session.close("auto")

    def list(self) -> list[SessionSummary]:
        with self.lock:
            sessions = list(self.sessions.values())
        return [session.status() for session in sessions]

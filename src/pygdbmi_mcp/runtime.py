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
    result: dict[str, Any] | None = None
    error: BaseException | None = None
    console: list[str] = field(default_factory=list)
    target: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    notifications: list[dict[str, Any]] = field(default_factory=list)
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

    @property
    def terminal(self) -> bool:
        return self.state in {
            "stopped",
            "exited",
            "cancelled",
            "timed_out",
            "failed",
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
        }


def _numeric_sort_key(value: str) -> tuple[int, str]:
    try:
        return (int(value), value)
    except ValueError:
        return (2**31 - 1, value)


def _inferior_number(group_id: str) -> int | None:
    match = re.fullmatch(r"i(\d+)", group_id)
    return int(match.group(1)) if match else None


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
        self._capabilities: dict[str, Any] | None = None
        self._capabilities_at: float | None = None
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
        self._reader.start()

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
        if self._io_reader is not None:
            self._io_reader.join(timeout=2.0)
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
                pending = _PendingCommand(token, command, time.monotonic())
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

            if record_type in {"exec", "notify", "status", "target", "log"}:
                self._event_cursor += 1
                self._events.append(
                    {
                        "cursor": self._event_cursor,
                        "received_at": time.time(),
                        "record": record,
                    }
                )
            self._update_state(record_type, message, payload)
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

    def interrupt(self, *, timeout_sec: float = 5.0) -> dict[str, Any]:
        with self.condition:
            before = self.stop_id
            if self.run_state == "stopped":
                return {"already_stopped": True, "session": self.status()}
        method = "mi"
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

    # -- retained execution operations ----------------------------------

    def start_execution(
        self,
        action: str,
        *,
        instruction: bool = False,
        location: str = "",
        timeout_sec: float = 0.0,
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
                    self._finish_job(job, "stopped")
                    self.condition.notify_all()
                    return
                remaining = None
                if job.timeout_sec:
                    remaining = job.timeout_sec - (time.monotonic() - started)
                    if remaining <= 0:
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
        interrupt = self.interrupt(timeout_sec=timeout_sec)
        with self.condition:
            if not job.terminal or job.state == "timed_out":
                self._finish_job(job, "cancelled")
            self.condition.notify_all()
            return {
                "already_terminal": False,
                "interrupt": interrupt,
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

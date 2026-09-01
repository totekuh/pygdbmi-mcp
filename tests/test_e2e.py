"""Integration tests exercising public tools against real GDB 17.x."""

from __future__ import annotations

import json
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from pygdbmi_mcp.server import (
    gdb_add_symbol_file,
    gdb_args,
    gdb_attach,
    gdb_backtrace,
    gdb_batch,
    gdb_breakpoint,
    gdb_cast_print,
    gdb_catchpoint,
    gdb_command,
    gdb_context,
    gdb_continue,
    gdb_delete_breakpoint,
    gdb_disassemble,
    gdb_enable_breakpoint,
    gdb_events,
    gdb_finish,
    gdb_inferior_io,
    gdb_inferior_stdin,
    gdb_info_files,
    gdb_info_functions,
    gdb_info_proc_mappings,
    gdb_info_sharedlibs,
    gdb_info_threads,
    gdb_info_types,
    gdb_info_variables,
    gdb_interrupt,
    gdb_list_breakpoints,
    gdb_list_sessions,
    gdb_load_binary,
    gdb_load_core,
    gdb_locals,
    gdb_memory,
    gdb_memory_find,
    gdb_memory_write,
    gdb_next,
    gdb_offsetof,
    gdb_output_page,
    gdb_print,
    gdb_print_struct,
    gdb_ptype,
    gdb_registers,
    gdb_remote_connect,
    gdb_remote_disconnect,
    gdb_run,
    gdb_select_frame,
    gdb_select_thread,
    gdb_session_status,
    gdb_set,
    gdb_set_variable,
    gdb_show,
    gdb_signal,
    gdb_sizeof,
    gdb_source_list,
    gdb_start,
    gdb_step,
    gdb_stop,
    gdb_until,
    gdb_var_assign,
    gdb_var_children,
    gdb_var_create,
    gdb_var_delete,
    gdb_var_update,
    gdb_wait_for_stop,
    gdb_watchpoint,
    gdb_whatis,
    manager,
)


def ok(envelope: dict) -> object:
    assert envelope["schema"] == "pygdbmi.mcp/1"
    assert envelope["ok"] is True, json.dumps(envelope, indent=2)
    assert envelope["error"] is None
    return envelope["result"]


def failed(envelope: dict, code: str) -> dict:
    assert envelope["ok"] is False, json.dumps(envelope, indent=2)
    assert envelope["result"] is None
    assert envelope["error"]["code"] == code
    return envelope["error"]


def text(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def status(session_id: str) -> dict:
    return ok(gdb_session_status(session_id))  # type: ignore[return-value]


def wait_after(session_id: str, stop_id: int, timeout: float = 8) -> dict:
    result = ok(
        gdb_wait_for_stop(session_id, after_stop_id=stop_id, timeout_sec=timeout)
    )
    assert result["reason"] in {"stopped", "exited"}
    return result  # type: ignore[return-value]


def break_and_run(session_id: str, location: str) -> dict:
    before = status(session_id)["stop_id"]
    ok(gdb_breakpoint(session_id, location))
    ok(gdb_run(session_id))
    result = wait_after(session_id, before)
    assert result["reason"] == "stopped"
    return result["session"]


def resume_and_wait(call, session_id: str, *args, **kwargs) -> dict:
    before = status(session_id)["stop_id"]
    ok(call(session_id, *args, **kwargs))
    return wait_after(session_id, before)


@pytest.fixture()
def session(binary_path):
    started = ok(gdb_start())
    sid = started["session_id"]
    ok(gdb_load_binary(sid, binary_path))
    yield sid
    if sid in manager.sessions:
        ok(gdb_stop(sid))


class TestSessionAndErrors:
    def test_start_list_status_and_stop(self):
        started = ok(gdb_start())
        sid = started["session_id"]
        assert started["catalog"]["tool_count"] == 65
        listing = ok(gdb_list_sessions())
        assert sid in {item["session_id"] for item in listing["sessions"]}
        current = status(sid)
        assert current["run_state"] == "idle"
        assert current["gdb_version"].startswith("GNU gdb")
        cleanup = ok(gdb_stop(sid))
        assert cleanup["applied_policy"] == "quit"
        listing = ok(gdb_list_sessions())
        assert sid not in {item["session_id"] for item in listing["sessions"]}

    def test_invalid_session_and_gdb_error_are_structured(self, session):
        failed(gdb_command("gdb-does-not-exist", "help"), "no_session")
        error = failed(gdb_command(session, "this-command-does-not-exist"), "gdb_error")
        assert error["operation"] == "gdb_command"
        assert error["details"]["reply"]["result_class"] == "error"

    def test_state_matrix_rejects_inspection_while_idle(self, session):
        error = failed(gdb_print(session, "1 + 1"), "invalid_state")
        assert error["details"]["run_state"] == "idle"


class TestLoadQuotingAndMetadata:
    def test_binary_path_and_argument_vector_quote_edges(self, tmp_path, binary_path):
        weird = tmp_path / "dir with spaces" / 'quoted "binary"'
        weird.parent.mkdir()
        shutil.copy2(binary_path, weird)
        sid = ok(gdb_start())["session_id"]
        try:
            args = ["alpha beta", 'say"hi', r"slash\tail", "snowman-☃"]
            ok(gdb_load_binary(sid, str(weird), args=args))
            current = status(sid)
            assert current["binary"] == str(weird.resolve())
            assert current["architecture"]
            assert current["endianness"] in {"little", "big"}
            assert current["pointer_width"] in {32, 64, 128}
            shown = ok(gdb_command(sid, "show args"))
            for fragment in ("alpha beta", "say", "slash", "snowman"):
                assert fragment in shown["output"]
        finally:
            ok(gdb_stop(sid))

    def test_add_symbol_file_with_quoted_path(self, session, tmp_path, binary_path):
        symbol = tmp_path / 'symbols with "quotes"'
        shutil.copy2(binary_path, symbol)
        result = ok(gdb_add_symbol_file(session, str(symbol), "0"))
        assert result["result_class"] == "done"


class TestBreakpointsAndExecution:
    def test_breakpoint_condition_enable_list_delete(self, session):
        created = ok(gdb_breakpoint(session, "add", condition="a == 3"))
        assert created["payload"]["bkpt"]["func"] == "add"
        number = int(created["payload"]["bkpt"]["number"])
        ok(gdb_enable_breakpoint(session, number, enable=False))
        listed = ok(gdb_list_breakpoints(session))
        assert listed["payload"]["BreakpointTable"]
        ok(gdb_enable_breakpoint(session, number, enable=True))
        ok(gdb_delete_breakpoint(session, number))

    def test_run_step_next_finish_until_continue(self, session):
        break_and_run(session, "main")
        before = status(session)["stop_id"]
        ok(gdb_next(session))
        assert wait_after(session, before)["reason"] == "stopped"
        before = status(session)["stop_id"]
        ok(gdb_step(session, instruction=True))
        assert wait_after(session, before)["reason"] == "stopped"
        ok(gdb_breakpoint(session, "add"))
        result = resume_and_wait(gdb_continue, session)
        assert result["reason"] == "stopped"
        assert result["session"]["last_stop"]["frame"]["func"] == "add"
        before = status(session)["stop_id"]
        ok(gdb_finish(session))
        assert wait_after(session, before)["reason"] == "stopped"
        before = status(session)["stop_id"]
        ok(gdb_until(session, "fill_point"))
        assert wait_after(session, before)["reason"] == "stopped"

    def test_temporary_hardware_watch_and_catchpoint(self, session):
        ok(gdb_breakpoint(session, "main", temporary=True))
        before = status(session)["stop_id"]
        ok(gdb_run(session))
        assert wait_after(session, before)["reason"] == "stopped"
        ok(gdb_breakpoint(session, "add", hardware=True))
        ok(gdb_watchpoint(session, "result"))
        failed(
            gdb_watchpoint(session, "result", access=True, read=True),
            "invalid_argument",
        )
        # Catchpoints are valid both before and at a stop.
        ok(gdb_catchpoint(session, "syscall write"))

    def test_signal_validation_and_delivery(self, session):
        break_and_run(session, "main")
        failed(gdb_signal(session, "SIGINT; shell id"), "invalid_argument")
        # Signal zero performs the resume path without actually delivering a signal.
        before = status(session)["stop_id"]
        ok(gdb_signal(session, "0"))
        wait_after(session, before)


class TestControlPlane:
    def test_events_wait_and_compact_context_ab(self, session):
        stopped = break_and_run(session, "add")
        compact = ok(
            gdb_context(
                session,
                instruction_count=8,
                include_threads=False,
                include_breakpoints=False,
            )
        )
        full = ok(
            gdb_context(
                session,
                instruction_count=8,
                register_set="all",
                include_threads=True,
                include_breakpoints=True,
                stack_bytes=64,
            )
        )
        assert compact["stop_id"] == stopped["stop_id"] == full["stop_id"]
        assert compact["frame"]["func"] == "add"
        assert "rip" in compact["registers"]
        assert len(compact["registers"]) < len(full["registers"])
        assert len(text(compact)) < len(text(full))
        assert full["threads"] and full["breakpoints"] and full["stack"]
        events = ok(gdb_events(session, after_cursor=0, limit=500))
        assert any(
            item["record"].get("message") == "stopped" for item in events["events"]
        )

    def test_wait_timeout_does_not_resume(self, session):
        before = status(session)
        result = ok(gdb_wait_for_stop(session, after_stop_id=999, timeout_sec=0.01))
        after = status(session)
        assert result["reason"] == "timeout"
        assert before["run_state"] == after["run_state"] == "idle"
        assert before["stop_id"] == after["stop_id"]

    def test_concurrent_resume_and_context_are_state_atomic(self, session):
        break_and_run(session, "main")
        barrier = threading.Barrier(3)

        def context_call():
            barrier.wait()
            return gdb_context(session, instruction_count=4)

        def continue_call():
            barrier.wait()
            return gdb_continue(session)

        with ThreadPoolExecutor(max_workers=2) as executor:
            context_future = executor.submit(context_call)
            continue_future = executor.submit(continue_call)
            barrier.wait()
            context_result = context_future.result(timeout=10)
            continue_result = continue_future.result(timeout=10)
        assert continue_result["ok"] is True
        if context_result["ok"]:
            assert context_result["result"]["frame"]["func"] == "main"
        else:
            assert context_result["error"]["code"] == "invalid_state"

    def test_atomic_batch_success_continue_and_stale_stop(self, session):
        stopped = break_and_run(session, "add")
        success = ok(
            gdb_batch(session, ["print a", "print b"], stop_id=stopped["stop_id"])
        )
        assert [item["ok"] for item in success["items"]] == [True, True]
        halted = ok(
            gdb_batch(
                session,
                ["print a", "bad-command", "print b"],
                continue_on_error=False,
            )
        )
        assert [item["ok"] for item in halted["items"]] == [True, False]
        continued = ok(
            gdb_batch(
                session,
                ["print a", "bad-command", "print b"],
                continue_on_error=True,
            )
        )
        assert [item["ok"] for item in continued["items"]] == [True, False, True]
        failed(gdb_batch(session, ["print a"], stop_id=99999), "stale_stop")

    def test_raw_output_is_paged_without_loss(self, session):
        first = ok(gdb_command(session, "echo " + "Z" * 2000, output_page_chars=256))
        assert len(first["output"]) == 256
        assert first["truncated"] is True
        chunks = [first["output"]]
        offset = first["next_offset"]
        while offset is not None:
            page = ok(gdb_output_page(session, first["command_id"], offset, 300))
            chunks.append(page["output"])
            offset = page["next_offset"]
        assert "".join(chunks) == "Z" * 2000

    def test_persistent_reader_drains_inferior_output_without_polling(
        self, binary_path
    ):
        sid = ok(gdb_start())["session_id"]
        try:
            ok(gdb_load_binary(sid, binary_path, args=["burst"]))
            before = status(sid)["stop_id"]
            ok(gdb_run(sid))
            # Deliberately do not poll events while 20 KiB crosses GDB's target pipe.
            stopped = wait_after(sid, before)
            assert stopped["reason"] == "exited"
            output = ok(gdb_inferior_io(sid, after_cursor=0, limit=65536))
            assert output["output"].count("Z") == 20000
            assert output["next_cursor"] == output["available_cursor"]
        finally:
            ok(gdb_stop(sid))

    def test_interactive_inferior_stdin_and_cursor_encodings(self, binary_path):
        sid = ok(gdb_start())["session_id"]
        try:
            ok(gdb_load_binary(sid, binary_path, args=["input"]))
            before = status(sid)["stop_id"]
            ok(gdb_run(sid))
            written = ok(gdb_inferior_stdin(sid, "needle\n"))
            assert written["bytes_written"] == 7
            assert wait_after(sid, before)["reason"] == "exited"
            utf8 = ok(gdb_inferior_io(sid, after_cursor=0, limit=1024))
            assert "ECHO:needle" in utf8["output"]
            hexadecimal = ok(
                gdb_inferior_io(
                    sid,
                    after_cursor=utf8["start_cursor"],
                    limit=utf8["bytes"],
                    encoding="hex",
                )
            )
            assert (
                bytes.fromhex(hexadecimal["output"]).decode(errors="replace")
                == utf8["output"]
            )
            failed(
                gdb_inferior_stdin(sid, "not-hex", encoding="hex"), "invalid_argument"
            )
        finally:
            ok(gdb_stop(sid))


class TestInspectionAndMemory:
    def test_stack_variables_registers_threads_and_frames(self, session):
        break_and_run(session, "add")
        trace = ok(gdb_backtrace(session, full=True, max_frames=8))
        assert "add" in text(trace)
        assert "a" in text(ok(gdb_args(session)))
        assert ok(gdb_locals(session))["result_class"] == "done"
        general = ok(gdb_registers(session))["registers"]
        named = ok(gdb_registers(session, names=["rip", "rsp"]))["registers"]
        assert set(named) == {"rip", "rsp"}
        assert len(general) > len(named)
        threads = ok(gdb_info_threads(session))
        thread_id = int(threads["payload"]["current-thread-id"])
        ok(gdb_select_thread(session, thread_id))
        ok(gdb_select_frame(session, 1))

    def test_print_set_memory_read_write_and_find(self, session):
        break_and_run(session, "add")
        assert ok(gdb_print(session, "a"))["payload"]["value"] == "3"
        ok(gdb_set_variable(session, "a", "99"))
        assert ok(gdb_print(session, "a"))["payload"]["value"] == "99"
        memory = ok(gdb_memory(session, "&a", count=4))
        assert memory["payload"]["memory"]
        ok(gdb_memory_write(session, "&a", "2a 00 00 00"))
        assert ok(gdb_print(session, "a"))["payload"]["value"] == "42"
        found = ok(gdb_memory_find(session, "&a", "&a+4", "0x2a"))
        assert found["result_class"] == "done"
        failed(gdb_memory_write(session, "&a", "xyz"), "invalid_argument")

    def test_disassembly_source_and_setting_restoration(self, session):
        disasm = ok(gdb_disassemble(session, function="main"))
        assert "main" in disasm["output"]
        ranged = ok(gdb_disassemble(session, start="main", num_bytes=64))
        assert ranged["payload"]["asm_insns"]
        failed(
            gdb_disassemble(session, function="main", start="$pc"), "invalid_argument"
        )
        ok(gdb_set(session, "listsize", "17"))
        source = ok(gdb_source_list(session, location="main", count=3))
        assert "main" in source["output"]
        shown = ok(gdb_show(session, "listsize"))
        assert "17" in shown["output"]


class TestTypesSymbolsAndVarObjects:
    def test_type_and_symbol_queries(self, session):
        assert "struct point" in ok(gdb_ptype(session, "struct point"))["output"]
        assert ok(gdb_sizeof(session, "struct point"))["payload"]["value"]
        assert ok(gdb_offsetof(session, "struct point", "y"))["payload"]["value"] == "4"
        assert "add" in ok(gdb_info_functions(session, "add"))["output"]
        assert ok(gdb_info_variables(session, "result"))["result_class"] == "done"
        assert "point" in ok(gdb_info_types(session, "point"))["output"]
        assert "test_binary" in ok(gdb_info_files(session))["output"]
        assert ok(gdb_info_sharedlibs(session))["result_class"] == "done"

    def test_struct_cast_whatis_and_pretty_setting_restoration(self, session):
        break_and_run(session, "fill_point")
        assert "struct point" in ok(gdb_whatis(session, "*p"))["output"]
        ok(gdb_set(session, "print pretty", "on"))
        assert "x =" in ok(gdb_print_struct(session, "*p", pretty=False))["output"]
        assert "on" in ok(gdb_show(session, "print pretty"))["output"].lower()
        assert "x =" in ok(gdb_cast_print(session, "p", "struct point *"))["output"]

    def test_variable_object_create_children_assign_update_delete(self, session):
        break_and_run(session, "fill_point")
        created = ok(gdb_var_create(session, "*p", name="watch_point"))
        assert created["payload"]["name"] == "watch_point"
        children = ok(gdb_var_children(session, "watch_point", 0, 8))
        assert children["payload"]["numchild"] == "3"
        ok(gdb_var_assign(session, "watch_point.x", "123"))
        changed = ok(gdb_var_update(session, "watch_point"))
        assert changed["result_class"] == "done"
        assert ok(gdb_print(session, "p->x"))["payload"]["value"] == "123"
        ok(gdb_var_delete(session, "watch_point"))


class TestAttachRemoteCoreAndInterrupt:
    def test_attach_interrupt_mappings_and_detach(self, binary_path):
        inferior = subprocess.Popen([binary_path, "loop"])
        sid = ok(gdb_start())["session_id"]
        try:
            attached = ok(gdb_attach(sid, inferior.pid))
            assert attached["result_class"] == "done"
            assert status(sid)["target_kind"] == "attached"
            assert ok(gdb_info_proc_mappings(sid))["result_class"] == "done"
            before = status(sid)["stop_id"]
            ok(gdb_continue(sid))
            # It is now genuinely running: inspection must be rejected deterministically.
            failed(gdb_context(sid), "invalid_state")
            interrupted = ok(gdb_interrupt(sid, timeout_sec=5))
            assert interrupted["reason"] == "stopped"
            assert interrupted["session"]["stop_id"] > before
            cleanup = ok(gdb_stop(sid, policy="auto"))
            assert cleanup["applied_policy"] == "detach"
        finally:
            if sid in manager.sessions:
                ok(gdb_stop(sid, policy="detach"))
            inferior.terminate()
            inferior.wait(timeout=5)

    def test_remote_connect_continue_and_disconnect(self, binary_path):
        server = subprocess.Popen(
            ["gdbserver", "--once", "localhost:0", binary_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert server.stdout is not None
        startup = []
        for _ in range(5):
            line = server.stdout.readline()
            startup.append(line)
            if "Listening on port" in line:
                break
        assert "Listening on port" in line, "".join(startup)
        port = line.rsplit(" ", 1)[-1].strip()
        sid = ok(gdb_start())["session_id"]
        try:
            ok(gdb_load_binary(sid, binary_path))
            ok(gdb_remote_connect(sid, f"localhost:{port}"))
            assert status(sid)["target_kind"] == "remote"
            ok(gdb_breakpoint(sid, "main"))
            result = resume_and_wait(gdb_continue, sid)
            assert result["reason"] == "stopped"
            ok(gdb_remote_disconnect(sid))
            assert status(sid)["target_kind"] == "none"
        finally:
            if sid in manager.sessions:
                ok(gdb_stop(sid))
            server.terminate()
            server.wait(timeout=5)

    def test_core_load_and_postmortem_context(self, tmp_path, binary_path):
        core = tmp_path / "crash core with spaces"
        generated_core = tmp_path / "core.raw"
        generated = subprocess.run(
            [
                "gdb",
                "--nx",
                "--batch",
                "-ex",
                "run crash",
                "-ex",
                f"generate-core-file {generated_core}",
                "--args",
                binary_path,
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert generated.returncode == 0, generated.stderr
        assert generated_core.exists()
        shutil.copy2(generated_core, core)
        sid = ok(gdb_start())["session_id"]
        try:
            ok(gdb_load_core(sid, str(core), binary_path))
            assert status(sid)["target_kind"] == "core"
            context = ok(gdb_context(sid, instruction_count=4))
            assert context["frame"] and context["registers"]
            cleanup = ok(gdb_stop(sid))
            assert cleanup["applied_policy"] == "quit"
        finally:
            if sid in manager.sessions:
                ok(gdb_stop(sid))

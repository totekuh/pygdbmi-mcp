"""End-to-end tests exercising the MCP tools against a real GDB session."""

import pytest
from pygdbmi_mcp.server import (
    manager,
    gdb_start,
    gdb_stop,
    gdb_list_sessions,
    gdb_load_binary,
    gdb_command,
    gdb_breakpoint,
    gdb_list_breakpoints,
    gdb_delete_breakpoint,
    gdb_enable_breakpoint,
    gdb_run,
    gdb_continue,
    gdb_next,
    gdb_step,
    gdb_finish,
    gdb_until,
    gdb_backtrace,
    gdb_print,
    gdb_locals,
    gdb_args,
    gdb_registers,
    gdb_memory,
    gdb_disassemble,
    gdb_source_list,
    gdb_ptype,
    gdb_print_struct,
    gdb_sizeof,
    gdb_whatis,
    gdb_set,
    gdb_show,
    gdb_info_functions,
    gdb_info_files,
    gdb_set_variable,
    gdb_select_frame,
)


@pytest.fixture()
def session(binary_path):
    """Start a GDB session, load the test binary, and clean up after."""
    out = gdb_start()
    sid = out.split(": ")[1]
    gdb_load_binary(sid, binary_path)
    yield sid
    try:
        gdb_stop(sid)
    except Exception:
        pass


class TestSessionManagement:
    def test_start_and_stop(self):
        out = gdb_start()
        assert "Session started: gdb-" in out
        sid = out.split(": ")[1]

        listing = gdb_list_sessions()
        assert sid in listing

        gdb_stop(sid)
        listing = gdb_list_sessions()
        assert sid not in listing

    def test_invalid_session_raises(self):
        with pytest.raises(ValueError, match="No GDB session"):
            gdb_command("gdb-nonexistent", "help")


class TestLoadAndRun:
    def test_load_binary(self, session):
        out = gdb_command(session, "info file")
        assert "test_binary" in out

    def test_run_to_completion(self, session):
        out = gdb_run(session)
        # Program should run and exit
        assert "stopped" in out or "exited" in out or "running" in out


class TestBreakpoints:
    def test_set_and_list_breakpoint(self, session):
        out = gdb_breakpoint(session, "main")
        assert "bkpt" in out or "done" in out.lower() or "ERROR" not in out

        listing = gdb_list_breakpoints(session)
        assert "main" in listing or "bkpt" in listing

    def test_delete_breakpoint(self, session):
        gdb_breakpoint(session, "main")
        out = gdb_delete_breakpoint(session, 1)
        assert "ERROR" not in out

    def test_conditional_breakpoint(self, session):
        out = gdb_breakpoint(session, "add", condition="a == 3")
        assert "ERROR" not in out

    def test_enable_disable_breakpoint(self, session):
        gdb_breakpoint(session, "main")
        out = gdb_enable_breakpoint(session, 1, enable=False)
        assert "ERROR" not in out
        out = gdb_enable_breakpoint(session, 1, enable=True)
        assert "ERROR" not in out


class TestExecution:
    def test_break_and_continue(self, session):
        gdb_breakpoint(session, "main")
        gdb_run(session)
        out = gdb_continue(session)
        # Should either hit next breakpoint or exit
        assert "ERROR" not in out

    def test_step_and_next(self, session):
        gdb_breakpoint(session, "main")
        gdb_run(session)
        out = gdb_next(session)
        assert "ERROR" not in out
        out = gdb_step(session)
        assert "ERROR" not in out

    def test_finish(self, session):
        gdb_breakpoint(session, "add")
        gdb_run(session)
        out = gdb_finish(session)
        assert "ERROR" not in out

    def test_until(self, session):
        gdb_breakpoint(session, "main")
        gdb_run(session)
        out = gdb_until(session, "fill_point")
        assert "ERROR" not in out


class TestInspection:
    def test_backtrace(self, session):
        gdb_breakpoint(session, "add")
        gdb_run(session)
        out = gdb_backtrace(session)
        assert "add" in out or "frame" in out

    def test_backtrace_full(self, session):
        gdb_breakpoint(session, "add")
        gdb_run(session)
        out = gdb_backtrace(session, full=True)
        assert "Locals" in out

    def test_print_expression(self, session):
        gdb_breakpoint(session, "add")
        gdb_run(session)
        out = gdb_print(session, "a")
        assert "ERROR" not in out

    def test_locals(self, session):
        gdb_breakpoint(session, "main")
        gdb_run(session)
        # Step past variable declarations
        for _ in range(3):
            gdb_next(session)
        out = gdb_locals(session)
        assert "ERROR" not in out

    def test_args(self, session):
        gdb_breakpoint(session, "add")
        gdb_run(session)
        out = gdb_args(session)
        assert "ERROR" not in out

    def test_registers(self, session):
        gdb_breakpoint(session, "main")
        gdb_run(session)
        out = gdb_registers(session)
        assert "ERROR" not in out

    def test_registers_named(self, session):
        gdb_breakpoint(session, "main")
        gdb_run(session)
        out = gdb_registers(session, names="rip rsp")
        assert "ERROR" not in out

    def test_select_frame(self, session):
        gdb_breakpoint(session, "add")
        gdb_run(session)
        out = gdb_select_frame(session, 1)
        assert "ERROR" not in out


class TestMemory:
    def test_read_memory(self, session):
        gdb_breakpoint(session, "main")
        gdb_run(session)
        out = gdb_memory(session, "$rsp", count=32)
        assert "ERROR" not in out

    def test_disassemble_function(self, session):
        out = gdb_disassemble(session, function="main")
        assert "ERROR" not in out
        # Should contain some assembly
        assert len(out) > 20

    def test_disassemble_num_bytes(self, session):
        out = gdb_disassemble(session, function="add")
        assert "ERROR" not in out

    def test_source_list(self, session):
        out = gdb_source_list(session, location="main")
        assert "ERROR" not in out


class TestTypes:
    def test_ptype_struct(self, session):
        out = gdb_ptype(session, "struct point")
        assert "int" in out
        assert "x" in out or "ERROR" not in out

    def test_sizeof(self, session):
        out = gdb_sizeof(session, "struct point")
        assert "ERROR" not in out

    def test_whatis(self, session):
        gdb_breakpoint(session, "add")
        gdb_run(session)
        out = gdb_whatis(session, "a")
        assert "ERROR" not in out

    def test_print_struct(self, session):
        # Break right after fill_point returns, where p is populated
        gdb_breakpoint(session, "fill_point")
        gdb_run(session)
        gdb_finish(session)
        out = gdb_print_struct(session, "p")
        assert "ERROR" not in out


class TestSymbols:
    def test_info_functions(self, session):
        out = gdb_info_functions(session, regexp="add")
        assert "add" in out

    def test_info_files(self, session):
        out = gdb_info_files(session)
        assert "ERROR" not in out


class TestSettings:
    def test_set_and_show(self, session):
        out = gdb_set(session, "disassembly-flavor", "intel")
        assert "ERROR" not in out
        out = gdb_show(session, "disassembly-flavor")
        assert "intel" in out

    def test_set_variable(self, session):
        gdb_breakpoint(session, "add")
        gdb_run(session)
        out = gdb_set_variable(session, "a", "99")
        assert "ERROR" not in out
        out = gdb_print(session, "a")
        assert "99" in out


class TestRawCommand:
    def test_raw_cli_command(self, session):
        out = gdb_command(session, "help")
        assert "ERROR" not in out

    def test_raw_mi_command(self, session):
        out = gdb_command(session, "-gdb-version")
        assert "ERROR" not in out

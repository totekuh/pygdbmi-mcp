"""ELF and static evidence helpers that do not need a live GDB session."""

from __future__ import annotations

import shutil
import subprocess
import threading

from pygdbmi_mcp.elf import inspect_elf, load_slide
from pygdbmi_mcp.research import _parse_mappings, collect_modules


def test_elf_identity_sections_build_id_and_slide(binary_path) -> None:
    identity = inspect_elf(binary_path, include_hash=True)
    assert identity["bits"] in {32, 64}
    assert identity["build_id"]
    assert len(identity["sha256"]) == 64
    assert any(item["name"] == ".text" for item in identity["sections"])
    segment = identity["segments"][0]
    page = min(segment["align"] or 4096, 4096)
    runtime = 0x7000_0000 + (segment["vaddr"] & ~(page - 1))
    mappings = [
        {
            "start": runtime,
            "offset": segment["offset"] & ~(page - 1),
        }
    ]
    assert load_slide(identity, mappings) == 0x7000_0000


def test_proc_mapping_parser_handles_permissions_and_anonymous_rows() -> None:
    parsed = _parse_mappings(
        """Mapped address spaces:
Start Addr End Addr Size Offset Perms File
0x1000 0x2000 0x1000 0x0 r-xp /bin/probe
0x3000 0x4000 0x1000 0x0 rw-p
"""
    )
    assert parsed == [
        {
            "start": 0x1000,
            "end": 0x2000,
            "size": 0x1000,
            "offset": 0,
            "permissions": "r-xp",
            "path": "/bin/probe",
        },
        {
            "start": 0x3000,
            "end": 0x4000,
            "size": 0x1000,
            "offset": 0,
            "permissions": "rw-p",
            "path": None,
        },
    ]


def test_elf_debuglink_is_normalized(tmp_path, binary_path) -> None:
    binary = tmp_path / "stripped"
    debug = tmp_path / "stripped.debug"
    shutil.copy2(binary_path, binary)
    subprocess.run(
        ["objcopy", "--only-keep-debug", binary, debug], check=True
    )
    subprocess.run(["objcopy", "--strip-debug", binary], check=True)
    subprocess.run(
        ["objcopy", f"--add-gnu-debuglink={debug}", binary], check=True
    )
    identity = inspect_elf(binary)
    assert identity["debuglink"] == "stripped.debug"
    assert identity["build_id"]


def test_module_elf_analysis_releases_the_gdb_command_lock(
    monkeypatch, binary_path
) -> None:
    class Session:
        command_lock = threading.RLock()
        stop_id = 7
        run_state = "stopped"
        sysroot = None
        binary = str(binary_path)
        debug_directories = []

        @staticmethod
        def execute(command, timeout_sec):
            if command == "-file-list-shared-libraries":
                return {"command_id": 2, "result_class": "done", "payload": {}}
            return {"command_id": 1, "result_class": "done", "output": ""}

    session = Session()
    observed = []

    def unlocked_inspect(path, include_hash=False):
        def probe():
            acquired = session.command_lock.acquire(timeout=0.5)
            observed.append(acquired)
            if acquired:
                session.command_lock.release()

        worker = threading.Thread(target=probe)
        worker.start()
        worker.join()
        return {
            "path": str(path),
            "type": "executable",
            "image_base": 0,
            "build_id": None,
            "segments": [],
            "sections": [],
        }

    monkeypatch.setattr("pygdbmi_mcp.research.inspect_elf", unlocked_inspect)
    result = collect_modules(session)
    assert observed == [True]
    assert result["stop_id"] == 7

"""Normalized reverse-engineering evidence and offline symbol adapters."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import OrderedDict
from pathlib import Path
from typing import Any

from .contracts import GdbMcpError, bounded_value
from .elf import ElfError, inspect_elf, load_slide
from .runtime import GdbSession, cli_quote


def _parse_mappings(output: str) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or not all(
            re.fullmatch(r"0x[0-9a-fA-F]+", item) for item in fields[:4]
        ):
            continue
        start, end, size, offset = (int(item, 16) for item in fields[:4])
        permissions = None
        path_index = 4
        if len(fields) > 4 and re.fullmatch(r"[rwxps-]{4,5}", fields[4]):
            permissions = fields[4]
            path_index = 5
        mappings.append(
            {
                "start": start,
                "end": end,
                "size": size,
                "offset": offset,
                "permissions": permissions,
                "path": " ".join(fields[path_index:]) or None,
            }
        )
    return mappings


def _symbol_files(output: str) -> list[str]:
    values: list[str] = []
    patterns = (
        r'^Symbols from "([^"]+)"',
        r"^(?:Local exec file|Exec file|Object file):\s+[`']([^`']+)'",
    )
    for line in output.splitlines():
        stripped = line.strip()
        for pattern in patterns:
            match = re.search(pattern, stripped)
            if match and match.group(1) not in values:
                values.append(match.group(1))
    return values


def _resolve_local_path(target_path: str, sysroot: str | None) -> str | None:
    raw = target_path.removeprefix("target:")
    direct = Path(raw).expanduser()
    if direct.is_file():
        return str(direct.resolve())
    if sysroot:
        rooted = Path(sysroot) / raw.lstrip("/")
        if rooted.is_file():
            return str(rooted.resolve())
    return None


def _debug_candidates(
    identity: dict[str, Any], debug_directories: list[str]
) -> list[dict[str, Any]]:
    path = Path(identity["path"])
    candidates: list[Path] = []
    debuglink = identity.get("debuglink")
    if debuglink:
        candidates.extend((path.parent / debuglink, path.parent / ".debug" / debuglink))
        for directory in debug_directories:
            candidates.append(Path(directory) / path.parent.as_posix().lstrip("/") / debuglink)
    build_id = identity.get("build_id")
    if isinstance(build_id, str) and len(build_id) >= 3:
        for directory in debug_directories:
            candidates.append(
                Path(directory) / ".build-id" / build_id[:2] / f"{build_id[2:]}.debug"
            )
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in candidates:
        value = str(candidate.expanduser())
        if value in seen:
            continue
        seen.add(value)
        unique.append({"path": value, "exists": candidate.is_file()})
    return unique[:64]


def collect_modules(
    session: GdbSession,
    *,
    include_sections: bool = False,
    include_hashes: bool = False,
    max_sections: int = 256,
    sysroot: str = "",
) -> dict[str, Any]:
    errors: dict[str, Any] = {}
    replies: dict[str, Any] = {}

    def query(name: str, command: str) -> dict[str, Any] | None:
        try:
            reply = session.execute(command, timeout_sec=30.0)
            replies[name] = {
                "command_id": reply.get("command_id"),
                "result_class": reply.get("result_class"),
            }
            return reply
        except GdbMcpError as exc:
            errors[name] = {"code": exc.code, "message": exc.message}
            return None

    with session.command_lock:
        if session.run_state not in {"idle", "stopped", "exited"}:
            raise GdbMcpError(
                f"module evidence is not available while the session is {session.run_state}",
                code="invalid_state",
                details={
                    "run_state": session.run_state,
                    "allowed_states": ["exited", "idle", "stopped"],
                },
                recovery=["Wait for a stop or interrupt the inferior."],
            )
        pinned_stop = session.stop_id if session.run_state == "stopped" else None
        mappings_reply = query("mappings", "info proc mappings")
        shared_reply = query("shared_libraries", "-file-list-shared-libraries")
        files_reply = query("symbol_files", "info files")
        root = (
            str(Path(sysroot).expanduser().resolve()) if sysroot else session.sysroot
        )
        binary = session.binary
        debug_dirs = list(session.debug_directories)

    # ELF inspection and hashing can be expensive. The GDB evidence above is a
    # coherent serialized snapshot; everything below is deliberately offline.
    mappings = _parse_mappings(
        mappings_reply.get("output", "") if mappings_reply else ""
    )
    shared_payload = shared_reply.get("payload") if shared_reply else None
    shared = (
        shared_payload.get("shared-libraries", [])
        if isinstance(shared_payload, dict)
        else []
    )
    symbol_files = _symbol_files(
        files_reply.get("output", "") if files_reply else ""
    )

    grouped: OrderedDict[str, list[dict[str, Any]]] = OrderedDict()
    anonymous: list[dict[str, Any]] = []
    for mapping in mappings:
        path = mapping.get("path")
        if isinstance(path, str) and path and not path.startswith("["):
            grouped.setdefault(path, []).append(mapping)
        else:
            anonymous.append(mapping)
    if binary:
        grouped.setdefault(binary, [])
    for item in shared if isinstance(shared, list) else []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        grouped.setdefault(str(item["name"]), [])

    modules: list[dict[str, Any]] = []
    for target_path, module_mappings in grouped.items():
        local_path = _resolve_local_path(target_path, root)
        identity = None
        identity_error = None
        slide = None
        sections: list[dict[str, Any]] | None = None
        if local_path:
            try:
                identity = inspect_elf(local_path, include_hash=include_hashes)
                slide = load_slide(identity, module_mappings)
                if slide is None and identity.get("type") == "executable":
                    slide = 0
                if include_sections:
                    sections = []
                    for section in identity["sections"][:max_sections]:
                        normalized = dict(section)
                        normalized["runtime_address"] = (
                            section["address"] + slide
                            if slide is not None and section["alloc"]
                            else None
                        )
                        sections.append(normalized)
            except (OSError, ElfError) as exc:
                identity_error = str(exc)[:2048]
        matching_shared = next(
            (
                item
                for item in shared
                if isinstance(item, dict) and str(item.get("name")) == target_path
            ),
            None,
        )
        runtime_start = min(
            (item["start"] for item in module_mappings),
            default=_hex_or_none(
                matching_shared.get("from") if matching_shared else None
            ),
        )
        runtime_end = max(
            (item["end"] for item in module_mappings),
            default=_hex_or_none(
                matching_shared.get("to") if matching_shared else None
            ),
        )
        compact_identity = None
        if identity:
            compact_identity = {
                key: value
                for key, value in identity.items()
                if key not in {"segments", "sections"}
            }
            compact_identity["segments"] = identity["segments"]
            compact_identity["debug_candidates"] = _debug_candidates(
                identity, debug_dirs
            )
        modules.append(
            {
                "module_id": len(modules) + 1,
                "target_path": target_path,
                "local_path": local_path,
                "runtime_start": runtime_start,
                "runtime_end": runtime_end,
                "load_slide": slide,
                "image_base": identity.get("image_base") if identity else None,
                "build_id": identity.get("build_id") if identity else None,
                "identity": compact_identity,
                "identity_error": identity_error,
                "mappings": module_mappings,
                "shared_library": bounded_value(matching_shared),
                "symbol_files": [
                    item
                    for item in symbol_files
                    if item == target_path
                    or (
                        local_path
                        and os.path.basename(item) == os.path.basename(local_path)
                    )
                ],
                "sections": sections,
            }
        )
    return {
        "revision": "pygdbmi.modules/1",
        "stop_id": pinned_stop,
        "sysroot": root,
        "modules": bounded_value(modules, max_items=max(512, max_sections * 8)),
        "module_count": len(modules),
        "anonymous_mappings": bounded_value(anonymous),
        "symbol_files": symbol_files,
        "partial": bool(errors or any(item["identity_error"] for item in modules)),
        "errors": errors,
        "replies": replies,
    }


def _hex_or_none(value: Any) -> int | None:
    try:
        return int(str(value), 0) if value is not None else None
    except (TypeError, ValueError):
        return None


def resolve_address(modules: dict[str, Any], address: int) -> dict[str, Any]:
    for module in modules.get("modules", []):
        for mapping in module.get("mappings", []):
            if mapping["start"] <= address < mapping["end"]:
                slide = module.get("load_slide")
                linked = address - slide if isinstance(slide, int) else None
                image_base = module.get("image_base")
                section = None
                for candidate in module.get("sections") or []:
                    runtime = candidate.get("runtime_address")
                    if isinstance(runtime, int) and runtime <= address < runtime + candidate["size"]:
                        section = candidate
                        break
                return {
                    "address": address,
                    "module": module,
                    "mapping": mapping,
                    "linked_address": linked,
                    "rva": (
                        linked - image_base
                        if isinstance(linked, int) and isinstance(image_base, int)
                        else None
                    ),
                    "section": section,
                }
    return {"address": address, "module": None, "mapping": None, "rva": None, "section": None}


def _load_symbol_entries(path: Path, format_name: str) -> list[tuple[int, str]]:
    if format_name == "plain":
        entries: list[tuple[int, str]] = []
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            raise GdbMcpError(
                f"could not read symbol file: {exc}", code="invalid_symbol_file"
            ) from exc
        for line_number, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                address, name = stripped.split(None, 1)
                entries.append((_parse_address(address), name.strip()))
            except (ValueError, TypeError) as exc:
                raise GdbMcpError(
                    f"invalid plain symbol at line {line_number}",
                    code="invalid_symbol_file",
                ) from exc
        return entries
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GdbMcpError(
            f"could not parse symbol JSON: {exc}", code="invalid_symbol_file"
        ) from exc
    if isinstance(value, dict):
        for key in ("functions", "exports", "symbols"):
            if isinstance(value.get(key), list):
                value = value[key]
                break
    if not isinstance(value, list):
        raise GdbMcpError(
            "symbol JSON must be an array or contain functions/exports/symbols",
            code="invalid_symbol_file",
        )
    entries = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise GdbMcpError(
                f"symbol entry {index} is not an object", code="invalid_symbol_file"
            )
        raw_address = item.get("address", item.get("entry", item.get("va")))
        name = item.get("name")
        try:
            address = _parse_address(raw_address)
        except (TypeError, ValueError) as exc:
            raise GdbMcpError(
                f"symbol entry {index} has an invalid address",
                code="invalid_symbol_file",
            ) from exc
        if not isinstance(name, str):
            raise GdbMcpError(
                f"symbol entry {index} has no name", code="invalid_symbol_file"
            )
        entries.append((address, name))
    return entries


def _parse_address(value: Any) -> int:
    rendered = str(value).strip()
    try:
        return int(rendered, 0)
    except ValueError:
        if re.fullmatch(r"[0-9a-fA-F]+", rendered):
            return int(rendered, 16)
        raise


def load_symbols_json(
    session: GdbSession,
    *,
    file: str,
    format_name: str,
    base_address: str,
    analysis_base_address: str,
    binary_path: str,
) -> dict[str, Any]:
    if format_name not in {"ghidra-decomp", "exports", "plain"}:
        raise GdbMcpError(
            "format must be ghidra-decomp, exports, or plain",
            code="invalid_argument",
        )
    source = Path(file).expanduser().resolve()
    if not source.is_file() or source.stat().st_size > 16 * 1024 * 1024:
        raise GdbMcpError(
            "symbol input must be a file no larger than 16 MiB",
            code="invalid_symbol_file",
        )
    binary = Path(binary_path or session.binary or "").expanduser().resolve()
    if not binary.is_file():
        raise GdbMcpError(
            "a local ELF binary_path is required to synthesize symbols",
            code="invalid_argument",
        )
    try:
        identity = inspect_elf(binary)
    except (OSError, ElfError) as exc:
        raise GdbMcpError(f"invalid symbol ELF: {exc}", code="invalid_argument") from exc
    entries = _load_symbol_entries(source, format_name)
    if not 1 <= len(entries) <= 10_000:
        raise GdbMcpError(
            "symbol input must contain 1 to 10000 entries", code="invalid_symbol_file"
        )
    sections = [item for item in identity["sections"] if item["alloc"] and item["size"]]
    arguments: list[str] = []
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    names: set[str] = set()
    valid_name = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$@?-]{0,255}\Z")
    analysis_base = None
    if analysis_base_address:
        try:
            analysis_base = _parse_address(analysis_base_address)
        except ValueError as exc:
            raise GdbMcpError(
                "analysis_base_address must be an integer such as 0x100000",
                code="invalid_argument",
            ) from exc
    for source_address, name in entries:
        address = (
            source_address - analysis_base + identity["image_base"]
            if analysis_base is not None
            else source_address
        )
        if not valid_name.fullmatch(name) or name in names:
            rejected.append(
                {
                    "address": source_address,
                    "name": name,
                    "reason": "invalid_or_duplicate_name",
                }
            )
            continue
        section = next(
            (
                item
                for item in sections
                if item["address"] <= address < item["address"] + item["size"]
            ),
            None,
        )
        if section is None:
            rejected.append(
                {
                    "address": source_address,
                    "name": name,
                    "reason": "outside_alloc_section",
                }
            )
            continue
        offset = address - section["address"]
        arguments.extend(
            ["--add-symbol", f"{name}={section['name']}:{offset:#x},function,global"]
        )
        accepted.append(
            {
                "source_address": source_address,
                "linked_address": address,
                "name": name,
                "section": section["name"],
            }
        )
        names.add(name)
    if not accepted:
        raise GdbMcpError(
            "no valid symbols mapped to allocated ELF sections",
            code="invalid_symbol_file",
            details={"rejected": rejected[:32]},
        )
    objcopy = shutil.which("objcopy")
    if not objcopy:
        raise GdbMcpError("objcopy is not installed", code="adapter_unavailable")
    directory = Path(tempfile.mkdtemp(prefix="pygdbmi-symbols-"))
    base_debug = directory / "base.debug"
    output = directory / "imported.debug"
    try:
        subprocess.run(
            [objcopy, "--only-keep-debug", str(binary), str(base_debug)],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        subprocess.run(
            [objcopy, *arguments, str(base_debug), str(output)],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        shutil.rmtree(directory, ignore_errors=True)
        detail = getattr(exc, "stderr", None) or str(exc)
        raise GdbMcpError(
            f"objcopy could not synthesize symbols: {detail}",
            code="symbol_generation_failed",
        ) from exc
    text_section = next((item for item in sections if item["name"] == ".text"), None)
    command = f"add-symbol-file {cli_quote(output)}"
    runtime_text = None
    effective_base = base_address
    inferred_base = False
    if not effective_base and identity["type"] == "shared" and session.run_state == "stopped":
        snapshot = collect_modules(session, include_sections=False)
        matched = next(
            (
                item
                for item in snapshot["modules"]
                if item.get("local_path") == str(binary)
                and isinstance(item.get("load_slide"), int)
            ),
            None,
        )
        if matched is not None:
            effective_base = hex(matched["load_slide"] + identity["image_base"])
            inferred_base = True
    if effective_base:
        try:
            runtime_base = int(effective_base, 0)
        except ValueError as exc:
            shutil.rmtree(directory, ignore_errors=True)
            raise GdbMcpError(
                "base_address must be an integer such as 0x400000",
                code="invalid_argument",
            ) from exc
        if text_section is None:
            shutil.rmtree(directory, ignore_errors=True)
            raise GdbMcpError("ELF has no .text section", code="invalid_argument")
        runtime_text = runtime_base + text_section["address"] - identity["image_base"]
        command += f" {runtime_text:#x}"
    try:
        with session.command_lock:
            if session.run_state not in {"idle", "stopped", "exited"}:
                raise GdbMcpError(
                    "generated symbols are ready but require a non-running target to load",
                    code="invalid_state",
                    details={"run_state": session.run_state},
                    recovery=["Interrupt the target, then retry symbol import."],
                )
            reply = session.execute(command, timeout_sec=60.0)
    except GdbMcpError:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    session._temporary_directories.append(str(directory))
    return {
        "format": format_name,
        "source": str(source),
        "binary": str(binary),
        "artifact": str(output),
        "base_address": effective_base or None,
        "base_address_inferred": inferred_base,
        "analysis_base_address": analysis_base,
        "runtime_text_address": runtime_text,
        "accepted": len(accepted),
        "rejected": len(rejected),
        "rejected_items": rejected[:64],
        "elf": {
            "build_id": identity["build_id"],
            "machine": identity["machine"],
            "bits": identity["bits"],
            "image_base": identity["image_base"],
        },
        "reply": reply,
    }

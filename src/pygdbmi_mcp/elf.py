"""Small dependency-free ELF identity reader used by debugger evidence tools."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any


_MACHINES = {
    3: "i386",
    8: "mips",
    20: "powerpc",
    21: "powerpc64",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}
_TYPES = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}


class ElfError(ValueError):
    pass


def _read_at(handle, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or size > 64 * 1024 * 1024:
        raise ElfError("invalid ELF range")
    handle.seek(offset)
    value = handle.read(size)
    if len(value) != size:
        raise ElfError("truncated ELF file")
    return value


def _cstring(table: bytes, offset: int) -> str:
    if not 0 <= offset < len(table):
        return ""
    end = table.find(b"\0", offset)
    if end < 0:
        end = len(table)
    return table[offset:end].decode("utf-8", errors="replace")[:4096]


def _note_build_id(data: bytes, endian: str) -> str | None:
    offset = 0
    while offset + 12 <= len(data):
        namesz, descsz, note_type = struct.unpack_from(endian + "III", data, offset)
        offset += 12
        name_end = offset + namesz
        desc_start = (name_end + 3) & ~3
        desc_end = desc_start + descsz
        if desc_end > len(data):
            return None
        name = data[offset:name_end].rstrip(b"\0")
        description = data[desc_start:desc_end]
        if name == b"GNU" and note_type == 3:
            return description.hex()
        offset = (desc_end + 3) & ~3
    return None


def inspect_elf(path: str | Path, *, include_hash: bool = False) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    with source.open("rb") as handle:
        ident = _read_at(handle, 0, 16)
        if ident[:4] != b"\x7fELF":
            raise ElfError("not an ELF file")
        elf_class = ident[4]
        data_encoding = ident[5]
        if elf_class not in {1, 2} or data_encoding not in {1, 2}:
            raise ElfError("unsupported ELF class or byte order")
        bits = 32 if elf_class == 1 else 64
        endian = "<" if data_encoding == 1 else ">"
        if bits == 32:
            header_format = endian + "HHIIIIIHHHHHH"
        else:
            header_format = endian + "HHIQQQIHHHHHH"
        header = struct.unpack(header_format, _read_at(handle, 16, struct.calcsize(header_format)))
        (
            elf_type,
            machine,
            _version,
            entry,
            phoff,
            shoff,
            _flags,
            _ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        ) = header
        if phnum > 4096 or shnum > 16384:
            raise ElfError("unreasonable ELF table size")

        program_headers: list[dict[str, Any]] = []
        note_ranges: list[tuple[int, int]] = []
        ph_format = endian + ("IIIIIIII" if bits == 32 else "IIQQQQQQ")
        ph_size = struct.calcsize(ph_format)
        if phnum and phentsize < ph_size:
            raise ElfError("invalid ELF program-header size")
        for index in range(phnum):
            values = struct.unpack(
                ph_format, _read_at(handle, phoff + index * phentsize, ph_size)
            )
            if bits == 32:
                p_type, offset, vaddr, _paddr, filesz, memsz, flags, align = values
            else:
                p_type, flags, offset, vaddr, _paddr, filesz, memsz, align = values
            if p_type == 1:
                program_headers.append(
                    {
                        "offset": offset,
                        "vaddr": vaddr,
                        "filesz": filesz,
                        "memsz": memsz,
                        "flags": flags,
                        "align": align,
                    }
                )
            elif p_type == 4 and filesz and filesz <= 16 * 1024 * 1024:
                note_ranges.append((int(offset), int(filesz)))

        raw_sections: list[tuple[int, ...]] = []
        sh_format = endian + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
        sh_size = struct.calcsize(sh_format)
        if shnum and shentsize < sh_size:
            raise ElfError("invalid ELF section-header size")
        for index in range(shnum):
            raw_sections.append(
                struct.unpack(
                    sh_format, _read_at(handle, shoff + index * shentsize, sh_size)
                )
            )
        names = b""
        if raw_sections and 0 <= shstrndx < len(raw_sections):
            name_section = raw_sections[shstrndx]
            names = _read_at(handle, int(name_section[4]), int(name_section[5]))

        sections: list[dict[str, Any]] = []
        build_id = None
        debuglink = None
        for values in raw_sections:
            name_offset, section_type, flags, address, offset, size = values[:6]
            name = _cstring(names, int(name_offset))
            section = {
                "name": name,
                "type": int(section_type),
                "flags": int(flags),
                "address": int(address),
                "offset": int(offset),
                "size": int(size),
                "alloc": bool(flags & 0x2),
                "executable": bool(flags & 0x4),
                "writable": bool(flags & 0x1),
            }
            sections.append(section)
            if section_type == 7 and size and size <= 16 * 1024 * 1024:
                candidate = _note_build_id(
                    _read_at(handle, int(offset), int(size)), endian
                )
                build_id = build_id or candidate
            if name == ".gnu_debuglink" and size and size <= 4096:
                debuglink = _cstring(_read_at(handle, int(offset), int(size)), 0)
        if build_id is None:
            for offset, size in note_ranges:
                build_id = _note_build_id(_read_at(handle, offset, size), endian)
                if build_id is not None:
                    break

    stat = source.stat()
    digest = None
    if include_hash:
        hasher = hashlib.sha256()
        with source.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
    bases = [
        item["vaddr"] - item["offset"]
        for item in program_headers
        if item["offset"] <= item["vaddr"]
    ]
    return {
        "path": str(source),
        "bits": bits,
        "endianness": "little" if data_encoding == 1 else "big",
        "type": _TYPES.get(elf_type, str(elf_type)),
        "machine": _MACHINES.get(machine, str(machine)),
        "machine_id": machine,
        "entry": entry,
        "image_base": min(bases) if bases else 0,
        "build_id": build_id,
        "debuglink": debuglink,
        "sha256": digest,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "segments": program_headers,
        "sections": sections,
    }


def load_slide(identity: dict[str, Any], mappings: list[dict[str, Any]]) -> int | None:
    """Infer one ELF load bias by matching PT_LOAD file offsets to mappings."""
    candidates: list[int] = []
    for mapping in mappings:
        start = mapping.get("start")
        file_offset = mapping.get("offset")
        if not isinstance(start, int) or not isinstance(file_offset, int):
            continue
        for segment in identity.get("segments", []):
            align = int(segment.get("align") or 4096)
            if align <= 0 or align > 2**30:
                align = 4096
            page = min(align, 4096)
            segment_offset = int(segment["offset"]) & ~(page - 1)
            if segment_offset != file_offset:
                continue
            segment_vaddr = int(segment["vaddr"]) & ~(page - 1)
            candidates.append(start - segment_vaddr)
    if not candidates:
        return None
    return max(set(candidates), key=candidates.count)

# pygdbmi-mcp roadmap

This project already exposes most day-to-day GDB commands. The missing work is
not another pile of command aliases; it is debugger control-plane reliability
and agent-sized evidence.

The design reference is Winbox `kdbg`, with a hard boundary: adopt its session,
state, event, bounding, and evidence patterns. Do not import QEMU RSP, CR3
masquerading, Windows PDB walking, CET handling, or the PyGhidra service into a
normal GDB MCP.

## Shipped in 0.2

Implemented in the current tree:

- One persistent reader owns each GDB process. Serialized commands use numeric
  MI tokens, so streams, async notifications, late replies, and command results
  cannot steal one another's reads.
- Explicit `idle`, `running`, `stopped`, `exited`, and `indeterminate` state is
  inferred from GDB/MI async records and enforced by a per-tool operation matrix.
- A monotonic `stop_id`, equivalent to kdbg's stop epoch, so clients can detect
  when evidence belongs to a different halt.
- Bounded cursor-based event polling for exec/notify/status records and inferior
  output.
- A bounded wait-for-stop tool for the async gap between `^running` and the
  later `*stopped` record.
- A compact stop-pinned `gdb_context` bundle with general-register defaults and
  opt-in all-registers, threads, breakpoints, and stack memory. Register-name
  tables are cached by session.
- One `pygdbmi.mcp/1` envelope for every tool and one typed error shape for
  invalid arguments/state, timeouts, missing sessions, GDB errors, stale stops,
  and reader failures.
- Cursor-paged retained command output, atomic bounded command batches, and
  incremental GDB/MI variable objects.
- Per-session inferior PTY ownership with bounded cursor output and bounded
  UTF-8/hex/base64 stdin for interactive local inferiors.
- Central MI/CLI encoding, exact inferior argument vectors, bounded inputs and
  results, target-aware cleanup, MCP annotations/instructions, and catalog
  revision/count identity.
- Target metadata for local/attach/remote/core workflows: PID, thread group,
  selected thread/frame, exit code, architecture, endianness, pointer width,
  and last error.

The command surface remains additive. Version 0.2 intentionally changes tool
results from ad-hoc strings to the versioned envelope; pretending that machine
clients benefit from prose errors was not a compatibility worth preserving.

## Completed — harden the MI boundary

1. Persistent reader and numeric MI correlation — done.
2. Versioned structured results and typed errors — done.
3. Central MI/CLI encoding and exact argv handling — done.
4. Result bounds, retained output pages, and event cursors — done.
5. Success-only target metadata updates and target identity — done.
6. Tested operation matrix for every public tool — done.

## P2 — make long debugger workflows survive agents

1. Inferior PTY ownership and bounded combined stdout/stderr plus stdin tools —
   shipped. Separate stdout/stderr is not possible through one Unix PTY; add a
   pipe mode later only if a real workflow needs the distinction.
2. Add a durable optional broker if execution must survive an MCP server process
   restart. Within one server lifetime, `run`/`continue`, stop epochs,
   `gdb_wait_for_stop`, and `gdb_interrupt` already provide start/poll/cancel
   semantics without holding a synchronous call open.
3. Atomic bounded batches and stop-pinned optional context memory — shipped.
4. Normalized register maps, register-name caching, and basic target traits —
   shipped. Capability/feature XML normalization remains.
5. GDB/MI variable-object create/update/children/assign/delete — shipped.
6. Support multi-inferior/fork/exec state explicitly, including follow-fork and
   detach-on-fork policies without pretending one PID field is the universe.

## P3 — reverse-engineering and post-mortem depth

1. Normalize mappings, ELF sections, shared objects, build IDs, symbol files,
   and relocation/load-slide evidence. Tie addresses to exact module identity.
2. Add bounded breakpoint command/action traces that auto-continue and retain a
   cursor-paged JSONL evidence stream, inspired by kdbg's conditional action
   traces.
3. Add optional adapters for `rr`, GDB `record full`/`record btrace`, and reverse
   execution. Keep capability detection explicit because targets lie and old
   GDB builds lie harder.
4. Add source-path and split-debug helpers (`set substitute-path`, debuglink,
   build-id directories, debuginfod status) with no hidden network fetches.
5. Consider an optional static-analysis/decompiler bridge only after exact
   module identity and stop-pinned RVA mapping exist. It should be a separate
   service, never loaded into the MCP/GDB process, and cold analysis must not
   hold a live inferior stopped.
6. If session survival across MCP server restarts becomes necessary, add an
   optional per-session broker process. Do not make a daemon mandatory merely
   because kdbg needs one for QEMU's single RSP owner.

## Current verification

- Unit coverage includes state transitions, token correlation, stray/late
  results, reader death, stop epochs, cursor gaps, event/output bounds,
  concurrency, timeouts/recovery, cleanup policy, quoting, envelopes, schemas,
  annotations, constraints, and catalog size/identity.
- Real-GDB coverage invokes all 65 tools across local run/stop/exit, attach and
  detach, async interrupt, remote `gdbserver`, core files with spaces,
  breakpoints/watchpoints/catchpoints, command paging, atomic batches, compact
  versus expanded context, settings restoration, variable objects, burst PTY
  output, and interactive stdin.
- CI runs the suite on Python 3.10–3.13 with GDB, gdbserver, and GCC.

Still worth adding: multi-thread/fork/exec regression targets, stripped PIE and
split-debug fixtures, large C++ var-object trees, non-x86 architecture CI, and a
real noisy interactive inferior once PTY ownership lands.

## Non-goals

- Reimplement GDB RSP while GDB already owns it.
- Pull Winbox's Windows kernel memory walkers into this repository.
- Ship a mandatory Ghidra/JVM dependency.
- Hide unbounded work behind a synchronous MCP call.

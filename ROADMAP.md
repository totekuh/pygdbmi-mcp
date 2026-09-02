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

## Shipped in 0.3

- A bounded per-session execution-job registry for run, continue, step, next,
  finish, and until. Jobs expose monotonic revisions, long polling, retained
  terminal results, explicit timeout-without-interrupt behavior, cancellation,
  and oldest-terminal eviction. This survives client calls, not MCP server
  process death.
- Normalized inferior/thread-group history with per-inferior PID, state,
  threads, exit code, executable, last stop, and exec count. Partial child exit
  no longer turns a live parent into a globally exited session.
- Inferior selection and transactional follow-fork/detach-on-fork/
  schedule-multiple policy with best-effort rollback on partial failure.
- Cached normalized capability manifests covering MI and target features,
  command availability, OS ABI, non-stop mode, architecture, endianness, pointer
  width, PTY support, and bounded per-probe errors.
- Multi-inferior local cleanup addresses every active inferior. The selected
  child being dead is no longer enough to leak its living parent.

## Shipped in 0.4

- Managed logging breakpoints retain bounded expression and backtrace hits,
  expose JSON/JSONL cursor pages, disable at a hit limit, and auto-continue
  without publishing a false client-visible stop epoch.
- Retained crash watches filter selected signals, make a previous `nostop`
  policy temporarily explicit, atomically collect backtrace/general registers/
  bounded memory, and restore the signal policy on capture, interruption, or
  timeout.
- Remote connect/disconnect notification compaction, inline architecture/
  sysroot/endian connection profiles, and partial-success bulk breakpoint
  insertion remove the repetitive agent round trips from embedded workflows.
- Normalized mapping/module evidence ties runtime ranges to local ELF build IDs,
  debuglinks, sections, symbol files, image bases, and calculated load slides.
  Runtime addresses can be resolved to a module, linked VA, RVA, and section.
- Bounded Ghidra/export/plain symbol import synthesizes a temporary companion
  ELF through optional GNU `objcopy`, infers stopped-PIE relocation when
  possible, and removes generated artifacts with the owning session.
- Optional `rr` replay startup, explicit `record btrace`/`record full` fallback,
  portable reverse execution, source substitution, split-debug directories,
  debuglink/build-ID candidates, and opt-in debuginfod configuration.

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
2. Server-lifetime retained execution jobs — shipped in 0.3. Add a durable
   optional broker only if execution must survive an MCP server process restart.
3. Atomic bounded batches and stop-pinned optional context memory — shipped.
4. Normalized register maps, register-name caching, target traits, and cached
   MI/target capability manifests — shipped. Parse remote feature XML later only
   when a consumer needs register-description detail beyond GDB's own model.
5. GDB/MI variable-object create/update/children/assign/delete — shipped.
6. Multi-inferior/fork/exec state, selection, cleanup, and fork policy — shipped
   in 0.3.

## Completed — reverse-engineering and post-mortem depth

1. Normalize mappings, ELF sections, shared objects, build IDs, symbol files,
   and relocation/load-slide evidence. Tie addresses to exact module identity —
   shipped in 0.4.
2. Add bounded breakpoint command/action traces that auto-continue and retain a
   cursor-paged JSONL evidence stream, inspired by kdbg's conditional action
   traces — shipped in 0.4.
3. Add optional adapters for `rr`, GDB `record full`/`record btrace`, and reverse
   execution. Keep capability detection explicit because targets lie and old
   GDB builds lie harder — shipped in 0.4.
4. Add source-path and split-debug helpers (`set substitute-path`, debuglink,
   build-id directories, debuginfod status) with no hidden network fetches —
   shipped in 0.4.
5. Consider an optional static-analysis/decompiler bridge only after exact
   module identity and stop-pinned RVA mapping exist. It should be a separate
   service, never loaded into the MCP/GDB process, and cold analysis must not
   hold a live inferior stopped — shipped in 0.4 as a bounded JSON-to-companion-
   ELF adapter process; no Ghidra/JVM is loaded into the MCP process.

## Deferred until a workflow requires it

- If session survival across MCP server restarts becomes necessary, add an
  optional per-session broker process. Do not make a daemon mandatory merely
  because kdbg needs one for QEMU's single RSP owner.

## Current verification

- Unit coverage includes state transitions, token correlation, stray/late
  results, reader death, stop epochs, cursor gaps, event/output bounds,
  concurrency, timeouts/recovery, cleanup policy, quoting, envelopes, schemas,
  annotations, constraints, and catalog size/identity.
- Real-GDB coverage invokes the 89-tool surface across local run/stop/exit,
  attach and detach, async interrupt, remote `gdbserver` launch and attach,
  all-stop/non-stop interrupt edges, core files with spaces,
  breakpoints/watchpoints/catchpoints, command paging, atomic batches, compact
  versus expanded context, settings restoration, variable objects, burst PTY
  output, interactive stdin, retained job timeout/cancel, cached capabilities,
  multi-inferior selection, fork child/parent exit, exec attribution, managed
  tracepoints, crash capture/policy restoration, connection profiles, compact
  notifications, stripped-PIE symbol import, module/RVA evidence, record/reverse
  execution, and source/split-debug configuration.
- CI runs the suite on Python 3.10–3.13 with GDB, gdbserver, and GCC.

Still worth adding: multi-thread non-stop regression targets, split-debug
fixtures, large C++ var-object trees, non-x86 architecture CI, and an optional
process broker only if restart persistence becomes a real need.

## Non-goals

- Reimplement GDB RSP while GDB already owns it.
- Pull Winbox's Windows kernel memory walkers into this repository.
- Ship a mandatory Ghidra/JVM dependency.
- Hide unbounded work behind a synchronous MCP call.

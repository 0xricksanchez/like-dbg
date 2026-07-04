# Crash capture: a dedicated pure-serial Console log, symbolized from KALLSYMS not System.map

Crash intelligence (B3, branch `feat/crash-intel`) needs a machine-parseable record of guest faults.
We capture the Debuggee's serial console into a dedicated byte-exact **Console log** (`console.raw`)
via a QEMU `-chardev … logfile=`, **replacing** the implicit `-nographic` stdio serial+monitor mux and
dropping stdio HMP access. We symbolize primarily from the kernel's own `CONFIG_KALLSYMS` output plus
the Debugger's live state captured at a panic-break trap, and **defer** `System.map`/`addr2line`
raw-address resolution to a later enrichment.

## Considered Options

- **Reuse the tmux operator-pane transcript.** Rejected: CRLF, `C-b B` restart gaps, and gdb interleave
  make it an unreliable parser input. The dedicated sink is a small, storage-mode-invariant QEMU change.
- **Keep the muxed stdio HMP monitor.** Rejected: `logfile=` on a muxed chardev lets HMP bytes pollute
  `console.raw`. Control is via gdb; a dedicated HMP/QMP socket arrives with B5.
- **System.map-centric symbolization.** Rejected: in volume mode the built tree (incl. `System.map`)
  lives in the Docker volume, not on the host, which would break the pure-host `--analyze-crash`; and
  with `CONFIG_KALLSYMS` on (base profile) the kernel already prints symbolic frames. System.map /
  `addr2line` remains available as later enrichment for raw addresses.

## Consequences

- `--analyze-crash` stays pure-host (Docker/tmux-free) in **both** storage modes.
- No stdio HMP monitor (`Ctrl-A c`) during a run; revisit with the B5 QMP/HMP socket.
- A build without `CONFIG_KALLSYMS` yields raw-address frames; the parser records them raw with a note
  rather than failing. A soft `CONFIG_KALLSYMS` expectation on crash-relevant profiles warns operators.

# Debug panes are tmux process panes, not interactive shells

Debuggee and Debugger panes are launched as **tmux process panes**: `split-window` or
`respawn-pane` starts the QEMU/GDB command directly, instead of opening an interactive shell
and feeding commands into it with `send-keys`.

This makes the pane process the debugging command itself. When QEMU or GDB exits, there is no
post-exit shell left behind in the Debuggee/Debugger panes, and no command text is written into
the user's shell history. Pane-local `remain-on-exit` keeps crash and exit output visible for
inspection after the process ends.

Restarting the Debuggee pane uses stored tmux session state (`@likedbg_*`) to find the original
command and pane, then restarts it in place with `respawn-pane -k`. The checked-in `.tmux.conf`
owns the recommended `C-b B` restart binding; runtime code does not mutate user tmux bindings.

## Consequences

- QEMU/GDB launches do **not** pollute shell history.
- Debuggee/Debugger panes do **not** leave an interactive shell behind after exit.
- Pane-local `remain-on-exit` keeps crash and exit output visible.
- Restart control is session-scoped through stored tmux state and `respawn-pane -k`.
- The checked-in `.tmux.conf` owns the recommended `C-b B` binding; application code does not
  call `bind-key` or otherwise mutate user bindings at runtime.

## Considered and rejected

- **`HISTFILE=/dev/null` or history-off shell setup.** Rejected: it still launches through an
  interactive shell and only masks one symptom of `send-keys`.
- **Continuing to use `send-keys`.** Rejected: it depends on shell state, writes command text as
  if a user typed it, and leaves a shell after the debug process exits.
- **Runtime `bind-key` mutation.** Rejected: user tmux bindings are configuration, not runtime
  application state. The project `.tmux.conf` is the right place for the recommended binding.
- **Global `remain-on-exit`.** Rejected: only Debuggee/Debugger process panes need this behavior;
  changing the global tmux setting would surprise unrelated panes.

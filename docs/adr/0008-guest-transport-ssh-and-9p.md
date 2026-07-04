# Guest control/transport: SSH over user-mode net + a 9p live share; host reaches the guest at localhost

The exploit deploy/run loop (2a, `feat/exploit-loop`) needs to push a payload into the running Debuggee,
run it with captured output, and keep the exploit's artifacts across a kernel panic. We wire **two** guest
transports: **SSH** as the control/exec channel (QEMU user-mode net + `virtio-net`, `hostfwd` guest `:22`
→ host `<ssh_port>`, using the rootfs's baked ed25519 key) and a **9p live share** (`-virtfs`, a persistent
host `exploit/` dir mounted rw at `/mnt/exploit`). `--run` reaches the guest at **`127.0.0.1:<ssh_port>`
in every topology** — the `hostfwd` binds `0.0.0.0` (`tcp::<port>`) exactly like the gdbstub, and the
in-container launcher publishes `-p <ssh_port>` (or shares host net in Linux `host` mode).

## Considered Options

- **SSH only.** Rejected as insufficient: a leak-then-panic exploit loses any files it wrote in-guest once
  the kernel dies (you can't `scp` after a crash) — only whatever stdout flushed over the live stream
  survives. 9p syncs artifacts to the host as they're written, so they survive the panic. This
  crash-durability is the reason for the second mechanism.
- **9p only.** Rejected: 9p moves files but gives no command channel, so running the exploit + capturing
  stdout/stderr would fall back to driving the serial console (fragile).
- **`host.docker.internal` for host→guest** (mirroring the unused `host_profile.ssh_addr`). Rejected: that
  is a container→guest address; `--run` runs on the host, and both native `hostfwd` and the in-container
  `-p` publish surface the port on host `localhost`. The dead `ssh_addr` field is removed to avoid implying
  otherwise.
- **`paramiko`.** Rejected: system `ssh`/`scp` needs no dependency and matches the existing subprocess-driven
  design (docker/tmux).

## Consequences

- `--run` is pure-host (Docker/tmux-free), targeting the live `latest` run — the run records the SSH
  endpoint + key path, like `--analyze-crash`.
- Binding `hostfwd` on `0.0.0.0` exposes guest SSH on the host's interfaces on native (same as the gdbstub;
  accepted for a dev tool).
- Building `custom_modules` (the vuln target) is explicitly out of scope here — that is 2b
  (`feat/custom-modules`), which reuses this transport.

# M1 Plan 3 — Boot & Debug (native HVF QEMU + gdb) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Boot the built arm64 kernel under **native HVF QEMU on the Mac**, attach the **containerized gdb** over `host.docker.internal`, and reach first the `start_kernel` breakpoint PoC, then a full **boot-to-shell session with interactive breakpoints** (the M1 exit gate).

**Architecture:** New deterministic units on the Plan 1/2 core: a docker-client resolver (honors the colima context), an artifact exporter (Docker volume → host workspace, for native QEMU), a typed **QEMU argv builder**, and gdb-invocation + rootfs command builders — all unit-tested with injected seams. The actual boot/attach orchestration (native QEMU as a host subprocess in a tmux pane; gdb in a container) is validated live in the empirical tasks.

**Tech Stack:** Python 3.12, Pydantic, docker-py, `qemu-system-aarch64 -accel hvf` (host), `gdb-multiarch`+GEF/pwndbg (container), tmux, colima; uv/ruff/mypy.

## Global Constraints

- Branching: `main` untouched. Work on feature branch `feat/m1-boot-debug` off `dev`; merge back after the final review. Live bring-up tasks run on a separate `feat/m1-live-boot` branch.
- Package boundary: new code under `src/likedbg/` (incl. `src/likedbg/stages/`); tests under `tests/`. Legacy flat `src/*.py` untouched (ruff `force-exclude`). `mypy --strict` clean over `src/likedbg`; `ruff check .`/`ruff format --check .` clean; line length 120. Run tools with `uv run`.
- Stages implement the `Stage` protocol (`name`/`run`/`should_skip`); errors use `LikeDbgError` subclasses with `remedy=`; side-effects behind injected seams so tests need no QEMU/Docker/host.
- Topology (spec §4.4): arm64-on-mac → **native HVF QEMU** (host subprocess), gdb in a container reaching `host.docker.internal:1234`. x86_64/Linux in-container is breadth (M2) — provide the seam, only wire/test native for M1.
- Storage (spec §4.6): in **volume mode** the built `vmlinux`/`Image` live in the `likedbg_ksrc` Docker volume; they MUST be exported to the host workspace before native QEMU can read them (Plan 2 bring-up finding).
- Docker client: `docker.from_env()` ignores the CLI context; on macOS/colima the client MUST be built from the active context's socket (Plan 2 bring-up finding).
- QEMU gdbstub on TCP `:1234` (`-S -s`); the debugger attaches over `host.docker.internal:1234` (from `HostProfile.gdbstub_addr`).

---

### Task 1: Docker client resolver (colima context)

`docker.from_env()` defaults to `/var/run/docker.sock` and ignores the CLI's active context, so it can't reach colima. Resolve the right socket.

**Files:**
- Create: `src/likedbg/docker_env.py`
- Create: `tests/test_docker_env.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `resolve_docker_host(*, env: Mapping[str, str], read_context_host: Callable[[], str | None]) -> str | None` — returns `env["DOCKER_HOST"]` if set; else `read_context_host()` (the active docker context's endpoint, e.g. `unix:///Users/u/.colima/default/docker.sock`); else `None` (use docker default).
  - `make_client(host: str | None) -> Any` — `docker.DockerClient(base_url=host)` if `host` else `docker.from_env()`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_docker_env.py`:

```python
from likedbg.docker_env import resolve_docker_host


def test_explicit_docker_host_env_wins():
    h = resolve_docker_host(env={"DOCKER_HOST": "unix:///x.sock"}, read_context_host=lambda: "unix:///ctx.sock")
    assert h == "unix:///x.sock"


def test_falls_back_to_context_when_env_unset():
    h = resolve_docker_host(env={}, read_context_host=lambda: "unix:///ctx.sock")
    assert h == "unix:///ctx.sock"


def test_none_when_neither_available():
    h = resolve_docker_host(env={}, read_context_host=lambda: None)
    assert h is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_docker_env.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.docker_env'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/docker_env.py`:

```python
"""Resolve the Docker client endpoint, honoring the active CLI context (colima)
since docker-py's from_env() ignores it."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from typing import Any


def _read_active_context_host() -> str | None:
    try:
        out = subprocess.run(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    host = out.stdout.strip()
    return host or None


def resolve_docker_host(*, env: Mapping[str, str], read_context_host: Any = _read_active_context_host) -> str | None:
    if env.get("DOCKER_HOST"):
        return env["DOCKER_HOST"]
    return read_context_host()


def make_client(host: str | None) -> Any:
    import docker

    if host:
        return docker.DockerClient(base_url=host)
    return docker.from_env()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_docker_env.py -v && uv run mypy src/likedbg`
Expected: 3 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/docker_env.py tests/test_docker_env.py
git commit -m "feat: docker client resolver honoring the active context (colima socket)"
```

---

### Task 2: Artifact exporter (volume → workspace)

In volume mode the built `Image`/`vmlinux` live in the Docker volume; native QEMU (host) can't read a volume. Export the needed single files to the host workspace.

**Files:**
- Create: `src/likedbg/stages/export.py`
- Create: `tests/test_stage_export.py`

**Interfaces:**
- Consumes: `PipelineContext`, `ContainerService`, `likedbg.errors.BuildError`.
- Produces:
  - `ArtifactExporter(container: ContainerService, *, kernel_volume: str, workspace: Path)` with `name = "export"`. `should_skip(ctx)` is true when `ctx.host.storage_mode != "volume"` (bind mode needs no export). `run(ctx)` copies `Image` + `vmlinux` from the volume to `<workspace>/artifacts/<kernel-id>/` and REWRITES `ctx.kernel_image`/`ctx.vmlinux` to the host paths so the debuggee/debugger read host files.
  - `host_artifact_dir(workspace: Path, kernel_root: Path) -> Path` → `workspace / "artifacts" / kernel_root.name`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_stage_export.py`:

```python
from pathlib import Path
from types import SimpleNamespace

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.export import ArtifactExporter


class FakeC(ContainerService):
    def __init__(self):
        self.execs = []
        self.run_kwargs = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _ctx(storage, tmp_path):
    host = HostProfile(os="darwin", host_arch="arm64", accel="hvf", debuggee_mode="native-host",
                       storage_mode=storage, gdbstub_addr="host.docker.internal", ssh_addr="host.docker.internal")
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_root = Path("/ksrc/linux-6.6.30")
    ctx.vmlinux = Path("/ksrc/linux-6.6.30/vmlinux")
    ctx.kernel_image = Path("/ksrc/linux-6.6.30/arch/arm64/boot/Image")
    return ctx


def test_skips_in_bind_mode(tmp_path):
    assert ArtifactExporter(FakeC(), kernel_volume="v", workspace=tmp_path).should_skip(_ctx("bind", tmp_path)) is True


def test_volume_mode_copies_and_rewrites_paths(tmp_path):
    c = FakeC()
    out = ArtifactExporter(c, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
    assert any("cp" in cmd for cmd in c.execs)
    assert "likedbg_ksrc" in str(c.run_kwargs["volumes"])
    assert out.kernel_image == tmp_path / "artifacts" / "linux-6.6.30" / "Image"
    assert out.vmlinux == tmp_path / "artifacts" / "linux-6.6.30" / "vmlinux"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_export.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.stages.export'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/stages/export.py`:

```python
"""Export stage: copy built single-file artifacts out of the kernel-source volume
to the host workspace, so native (host) QEMU can read them. No-op in bind mode."""

from __future__ import annotations

from pathlib import Path

from likedbg.container_service import ContainerService
from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext

_VOLUME_MOUNT = "/ksrc"
_OUT_MOUNT = "/out"
_BASE_IMAGE = "like_dbg_base"


def host_artifact_dir(workspace: Path, kernel_root: Path) -> Path:
    return workspace / "artifacts" / kernel_root.name


class ArtifactExporter:
    name = "export"

    def __init__(self, container: ContainerService, *, kernel_volume: str, workspace: Path) -> None:
        self._c = container
        self._volume = kernel_volume
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        return ctx.host.storage_mode != "volume"

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_root is None or ctx.vmlinux is None or ctx.kernel_image is None:
            raise BuildError("missing build artifacts in context", remedy="run the Build stage first")
        out_dir = host_artifact_dir(self._workspace, ctx.kernel_root)
        out_dir.mkdir(parents=True, exist_ok=True)
        rel_vmlinux = ctx.vmlinux.relative_to(_VOLUME_MOUNT)
        rel_image = ctx.kernel_image.relative_to(_VOLUME_MOUNT)
        volumes = {
            self._volume: {"bind": _VOLUME_MOUNT, "mode": "ro"},
            str(out_dir): {"bind": _OUT_MOUNT, "mode": "rw"},
        }
        container = self._c.run_detached(_BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"cp {_VOLUME_MOUNT}/{rel_vmlinux} {_OUT_MOUNT}/vmlinux")
            self._c.exec(container, f"cp {_VOLUME_MOUNT}/{rel_image} {_OUT_MOUNT}/Image")
        finally:
            self._c.stop(container)
        ctx.vmlinux = out_dir / "vmlinux"
        ctx.kernel_image = out_dir / "Image"
        return ctx
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_export.py -v && uv run mypy src/likedbg`
Expected: 2 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/export.py tests/test_stage_export.py
git commit -m "feat: artifact export stage (volume -> host workspace for native QEMU)"
```

---

### Task 3: QEMU argv builder

The typed core of the debuggee: build the `qemu-system-<arch>` argv (machine/cpu/accel/mem/mitigations/console/gdbstub/rootfs), replacing the legacy string concatenation.

**Files:**
- Create: `src/likedbg/qemu.py`
- Create: `tests/test_qemu.py`

**Interfaces:**
- Consumes: `likedbg.config.Settings`, `likedbg.host_profile.HostProfile`.
- Produces:
  - `build_qemu_argv(settings: Settings, host: HostProfile, *, kernel_image: Path, rootfs: Path | None) -> list[str]` — for arm64: `qemu-system-aarch64 -M virt -cpu host -accel hvf` (when `host.accel == "hvf"`, else `-accel tcg`/`kvm`), `-m <mem> -smp <smp>`, `-kernel <image>`, an `-append "console=ttyAMA0 ... <mitigations> ..."`, `-nographic`, `-S -s` when `settings.debuggee.gdb`. Mitigations from `settings.debuggee` (`nokaslr` when `kaslr` is false, etc.). Rootfs (if given) inferred: `*.cpio*` → `-initrd <rootfs>` + `root=/dev/ram`; else `-drive file=<rootfs>,format=raw,if=virtio` + `root=/dev/vda`. x86_64: `qemu-system-x86_64 -cpu qemu64[,+smep,+smap] -append "console=ttyS0 ..."`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_qemu.py`:

```python
from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.qemu import build_qemu_argv


def _host(arch_accel="hvf", mode="native-host"):
    return HostProfile(os="darwin", host_arch="arm64", accel=arch_accel, debuggee_mode=mode,
                       storage_mode="volume", gdbstub_addr="host.docker.internal", ssh_addr="host.docker.internal")


def _settings(arch="arm64", **debuggee):
    base = {"memory": 1024, "smp": 1, "gdb": True, "kaslr": False}
    base.update(debuggee)
    return Settings.model_validate({"general": {"arch": arch}, "debuggee": base})


def _argstr(argv):
    return " ".join(argv)


def test_arm64_hvf_machine_and_accel():
    argv = build_qemu_argv(_settings("arm64"), _host("hvf"), kernel_image=Path("/w/Image"), rootfs=None)
    assert argv[0] == "qemu-system-aarch64"
    s = _argstr(argv)
    assert "-M virt" in s and "-accel hvf" in s and "-kernel /w/Image" in s


def test_gdbstub_flags_present_when_gdb_enabled():
    argv = build_qemu_argv(_settings("arm64", gdb=True), _host(), kernel_image=Path("/w/Image"), rootfs=None)
    assert "-S" in argv and "-s" in argv


def test_no_gdbstub_when_disabled():
    argv = build_qemu_argv(_settings("arm64", gdb=False), _host(), kernel_image=Path("/w/Image"), rootfs=None)
    assert "-S" not in argv


def test_nokaslr_in_append_when_kaslr_false():
    argv = build_qemu_argv(_settings("arm64", kaslr=False), _host(), kernel_image=Path("/w/Image"), rootfs=None)
    append = argv[argv.index("-append") + 1]
    assert "nokaslr" in append and "console=ttyAMA0" in append


def test_cpio_rootfs_uses_initrd():
    argv = build_qemu_argv(_settings("arm64"), _host(), kernel_image=Path("/w/Image"), rootfs=Path("/w/rootfs.cpio.gz"))
    s = _argstr(argv)
    assert "-initrd /w/rootfs.cpio.gz" in s


def test_ext4_rootfs_uses_drive():
    argv = build_qemu_argv(_settings("arm64"), _host(), kernel_image=Path("/w/Image"), rootfs=Path("/w/rootfs.img"))
    s = _argstr(argv)
    assert "-drive" in s and "rootfs.img" in s
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_qemu.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.qemu'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/qemu.py`:

```python
"""Typed QEMU argv builder (replaces the legacy string concatenation)."""

from __future__ import annotations

from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile

_QEMU_BIN = {"arm64": "qemu-system-aarch64", "x86_64": "qemu-system-x86_64"}


def _mitigations(settings: Settings) -> list[str]:
    d = settings.debuggee
    out: list[str] = []
    out.append("nokaslr" if not d.kaslr else "kaslr")
    if not d.smep:
        out.append("nosmep")
    if not d.smap:
        out.append("nosmap")
    out.append("pti=on" if d.kpti else "nopti")
    return out


def _panic(settings: Settings) -> str:
    p = settings.debuggee.panic
    if p == "reboot":
        return "panic=-1"
    if p == "halt":
        return "panic=0"
    return "panic=15"


def _rootfs_args(rootfs: Path | None) -> tuple[list[str], str]:
    if rootfs is None:
        return [], "root=/dev/ram"
    if ".cpio" in rootfs.name:
        return ["-initrd", str(rootfs)], "root=/dev/ram"
    return ["-drive", f"file={rootfs},format=raw,if=virtio"], "root=/dev/vda"


def build_qemu_argv(
    settings: Settings, host: HostProfile, *, kernel_image: Path, rootfs: Path | None
) -> list[str]:
    arch = settings.general.arch
    argv = [_QEMU_BIN[arch]]
    if arch == "arm64":
        argv += ["-M", "virt", "-cpu", "host" if host.accel == "hvf" else "cortex-a72"]
        console = "console=ttyAMA0"
    else:
        cpu = "qemu64"
        if settings.debuggee.smep:
            cpu += ",+smep"
        if settings.debuggee.smap:
            cpu += ",+smap"
        argv += ["-cpu", cpu]
        console = "console=ttyS0"
    argv += ["-accel", host.accel, "-m", str(settings.debuggee.memory), "-smp", str(settings.debuggee.smp)]
    argv += ["-kernel", str(kernel_image)]
    drive_args, root = _rootfs_args(rootfs)
    append = " ".join([console, root, "earlyprintk=serial", *_mitigations(settings), "oops=panic", _panic(settings)])
    argv += ["-append", append, *drive_args, "-nographic"]
    if settings.debuggee.gdb:
        argv += ["-S", "-s"]
    return argv
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_qemu.py -v && uv run mypy src/likedbg`
Expected: 6 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/qemu.py tests/test_qemu.py
git commit -m "feat: typed QEMU argv builder (arch/accel/mitigations/gdbstub/rootfs)"
```

---

### Task 4: gdb invocation builder

Build the gdb command that attaches to the gdbstub over TCP, loads `vmlinux`, and breaks at a symbol — corrected `gef-remote` form (no `--qemu-user`).

**Files:**
- Create: `src/likedbg/gdbcmd.py`
- Create: `tests/test_gdbcmd.py`

**Interfaces:**
- Consumes: `likedbg.host_profile.HostProfile`, `likedbg.config.Ext`.
- Produces:
  - `build_gdb_args(host: HostProfile, *, vmlinux: Path, ext: str, breakpoint: str | None) -> list[str]` — `gdb-multiarch -q <vmlinux> -ex "set architecture aarch64" -ex "target remote <addr>:1234"` (pwndbg) or `-ex "gef-remote <addr> 1234"` (gef; NOT `--qemu-user`), then `-ex "break <breakpoint>"` + `-ex "continue"` when a breakpoint is given, plus the kernel-helper `-ex` lines. `<addr>` = `host.gdbstub_addr`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_gdbcmd.py`:

```python
from pathlib import Path

from likedbg.gdbcmd import build_gdb_args
from likedbg.host_profile import HostProfile


def _host(addr="host.docker.internal"):
    return HostProfile(os="darwin", host_arch="arm64", accel="hvf", debuggee_mode="native-host",
                       storage_mode="volume", gdbstub_addr=addr, ssh_addr=addr)


def test_pwndbg_uses_target_remote_with_addr():
    args = build_gdb_args(_host(), vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint="start_kernel")
    s = " ".join(args)
    assert "target remote host.docker.internal:1234" in s
    assert "/w/vmlinux" in s
    assert "break start_kernel" in s


def test_gef_uses_gef_remote_not_qemu_user():
    args = build_gdb_args(_host(), vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None)
    s = " ".join(args)
    assert "gef-remote host.docker.internal 1234" in s
    assert "--qemu-user" not in s


def test_no_breakpoint_omits_break():
    args = build_gdb_args(_host(), vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None)
    assert all("break" not in a for a in args)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_gdbcmd.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.gdbcmd'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/gdbcmd.py`:

```python
"""Build the gdb invocation that attaches to the QEMU gdbstub over TCP."""

from __future__ import annotations

from pathlib import Path

from likedbg.host_profile import HostProfile


def build_gdb_args(host: HostProfile, *, vmlinux: Path, ext: str, breakpoint: str | None) -> list[str]:
    addr = host.gdbstub_addr
    args = ["gdb-multiarch", "-q", str(vmlinux), "-ex", "set architecture aarch64"]
    if ext == "gef":
        args += ["-ex", f"gef-remote {addr} 1234"]
    else:
        args += ["-ex", f"target remote {addr}:1234"]
    args += ["-ex", "add-auto-load-safe-path /"]
    if breakpoint is not None:
        args += ["-ex", f"break {breakpoint}", "-ex", "continue"]
    return args
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_gdbcmd.py -v && uv run mypy src/likedbg`
Expected: 3 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/gdbcmd.py tests/test_gdbcmd.py
git commit -m "feat: gdb invocation builder (correct gef-remote / target remote, TCP attach)"
```

---

### Task 5: Rootfs stage (arm64 native, debootstrap)

Build an arm64 root filesystem image via the existing (resolv.conf-fixed) `rootfs.sh` in a privileged container. Native arch only for M1 (no foreign binfmt).

**Files:**
- Create: `src/likedbg/stages/rootfs.py`
- Create: `tests/test_stage_rootfs.py`
- Modify: `io/scripts/rootfs.sh:173` (fix `resolve.conf` → `resolv.conf`)
- Modify: `src/likedbg/pipeline.py` (add `rootfs_image` already exists from Plan 2 — confirm; no change if present)

**Interfaces:**
- Consumes: `PipelineContext` (`ctx.settings.rootfs`, `ctx.settings.general.arch`), `ContainerService`, `likedbg.errors.RootfsError`.
- Produces:
  - `RootfsStage(container: ContainerService, *, rootfs_image: str, workspace: Path, out_subdir: str = "artifacts")` with `name = "rootfs"`, `should_skip(ctx)` true when the target image already exists on the host, `run(ctx)` running `rootfs.sh` in a privileged container and setting `ctx.rootfs_image` to the host path of the produced image.
  - `rootfs_target(workspace: Path, arch: str) -> Path` → `workspace / "artifacts" / f"rootfs-{arch}.img"`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_stage_rootfs.py`:

```python
from pathlib import Path
from types import SimpleNamespace

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.rootfs import RootfsStage
from likedbg.stages.rootfs import rootfs_target


class FakeC(ContainerService):
    def __init__(self):
        self.run_kwargs = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1", logs=lambda **k: iter([b"building\n"]))

    def exec(self, container, cmd, *, workdir=None):
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _ctx(tmp_path):
    host = HostProfile(os="darwin", host_arch="arm64", accel="hvf", debuggee_mode="native-host",
                       storage_mode="volume", gdbstub_addr="x", ssh_addr="x")
    return PipelineContext(settings=Settings(), host=host)


def test_rootfs_target_path():
    assert rootfs_target(Path("/ws"), "arm64") == Path("/ws/artifacts/rootfs-arm64.img")


def test_run_starts_privileged_container_and_sets_rootfs(tmp_path):
    c = FakeC()
    out = RootfsStage(c, rootfs_image="like_rootfs", workspace=tmp_path).run(_ctx(tmp_path))
    assert c.run_kwargs["privileged"] is True
    assert out.rootfs_image == tmp_path / "artifacts" / "rootfs-arm64.img"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_rootfs.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.stages.rootfs'`.

- [ ] **Step 3: Fix the rootfs.sh typo**

In `io/scripts/rootfs.sh`, change the `resolve.conf` filename to `resolv.conf` (the DNS file). Confirm with `grep -n "resolv" io/scripts/rootfs.sh` — there should be no `resolve.conf` left.

- [ ] **Step 4: Write the implementation**

Create `src/likedbg/stages/rootfs.py`:

```python
"""Rootfs stage: build a native-arch root filesystem image via rootfs.sh in a
privileged container, and record its host path."""

from __future__ import annotations

from pathlib import Path

from likedbg.container_service import ContainerService
from likedbg.errors import RootfsError
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"


def rootfs_target(workspace: Path, arch: str) -> Path:
    return workspace / "artifacts" / f"rootfs-{arch}.img"


class RootfsStage:
    name = "rootfs"

    def __init__(self, container: ContainerService, *, rootfs_image: str, workspace: Path) -> None:
        self._c = container
        self._image = rootfs_image
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        return rootfs_target(self._workspace, ctx.settings.general.arch).exists()

    def run(self, ctx: PipelineContext) -> PipelineContext:
        arch = ctx.settings.general.arch
        target = rootfs_target(self._workspace, arch)
        target.parent.mkdir(parents=True, exist_ok=True)
        cfg = ctx.settings.rootfs
        qemu_arch = "aarch64" if arch == "arm64" else "x86_64"
        name = target.name
        cmd = (
            f"/bin/bash -lc '. /home/user/rootfs.sh -n {name} -a {qemu_arch} "
            f"-d {cfg.distribution} -u user -h {cfg.hostname}'"
        )
        try:
            container = self._c.run_detached(
                self._image,
                volumes={str(target.parent): {"bind": _MOUNT, "mode": "rw"}},
                privileged=True, detach=True, command=cmd,
            )
        except Exception as exc:  # noqa: BLE001
            raise RootfsError("failed to start rootfs build container", remedy="check the rootfs image exists") from exc
        for line in container.logs(stream=True, follow=True):
            _ = line
        self._c.stop(container)
        ctx.rootfs_image = target
        return ctx
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_rootfs.py -v && uv run mypy src/likedbg`
Expected: 2 passed; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/stages/rootfs.py tests/test_stage_rootfs.py io/scripts/rootfs.sh
git commit -m "feat: rootfs stage (native arm64 debootstrap); fix resolv.conf typo"
```

---

### Task 6: Debuggee + Debugger launchers

Wrap the argv/gdb builders in `Stage`s that launch native QEMU (host subprocess) and containerized gdb. Launch is behind injected runners so it's unit-testable; the real boot is Task 7/8.

**Files:**
- Create: `src/likedbg/stages/debuggee.py`
- Create: `src/likedbg/stages/debugger.py`
- Create: `tests/test_stage_debuggee.py`
- Create: `tests/test_stage_debugger.py`

**Interfaces:**
- Consumes: `PipelineContext`, `likedbg.qemu.build_qemu_argv`, `likedbg.gdbcmd.build_gdb_args`, `likedbg.errors.BuildError`.
- Produces:
  - `DebuggeeStage(*, launch: Callable[[list[str]], None])` — `name="debuggee"`; `run(ctx)` builds the argv (`build_qemu_argv` with `ctx.kernel_image`/`ctx.rootfs_image`) and calls `launch(argv)` (the wiring's `launch` closes over the tmux pane / host subprocess). `should_skip` false.
  - `DebuggerStage(*, ext: str, run_gdb: Callable[[list[str]], None], breakpoint: str | None)` — `name="debugger"`; `run(ctx)` builds gdb args (`build_gdb_args` with `ctx.vmlinux`) and calls `run_gdb(args)`. `should_skip` false. (The tmux `Session` is wired in by the empirical assembly, Tasks 7–8, not the stage.)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_stage_debuggee.py`:

```python
from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.debuggee import DebuggeeStage


def _ctx():
    host = HostProfile(os="darwin", host_arch="arm64", accel="hvf", debuggee_mode="native-host",
                       storage_mode="volume", gdbstub_addr="host.docker.internal", ssh_addr="host.docker.internal")
    ctx = PipelineContext(settings=Settings.model_validate({"general": {"arch": "arm64"}}), host=host)
    ctx.kernel_image = Path("/ws/artifacts/linux-6.6.30/Image")
    return ctx


def test_native_debuggee_launches_qemu_argv():
    launched = {}
    stage = DebuggeeStage(launch=lambda argv: launched.setdefault("argv", argv))
    stage.run(_ctx())
    assert launched["argv"][0] == "qemu-system-aarch64"
    assert "-kernel" in launched["argv"]
```

Create `tests/test_stage_debugger.py`:

```python
from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.debugger import DebuggerStage


def _ctx():
    host = HostProfile(os="darwin", host_arch="arm64", accel="hvf", debuggee_mode="native-host",
                       storage_mode="volume", gdbstub_addr="host.docker.internal", ssh_addr="host.docker.internal")
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.vmlinux = Path("/ws/artifacts/linux-6.6.30/vmlinux")
    return ctx


def test_debugger_builds_and_runs_gdb_with_breakpoint():
    ran = {}
    stage = DebuggerStage(ext="gef", run_gdb=lambda args: ran.setdefault("args", args), breakpoint="start_kernel")
    stage.run(_ctx())
    s = " ".join(ran["args"])
    assert "gef-remote host.docker.internal 1234" in s and "break start_kernel" in s
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_stage_debuggee.py tests/test_stage_debugger.py -v`
Expected: FAIL (modules not found).

- [ ] **Step 3: Write the implementations**

Create `src/likedbg/stages/debuggee.py`:

```python
"""Debuggee stage: launch QEMU (native host subprocess for arm64-on-mac)."""

from __future__ import annotations

from collections.abc import Callable

from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext
from likedbg.qemu import build_qemu_argv


class DebuggeeStage:
    name = "debuggee"

    def __init__(self, *, launch: Callable[[list[str]], None]) -> None:
        self._launch = launch

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_image is None:
            raise BuildError("no kernel image in context", remedy="run the Build/Export stages first")
        argv = build_qemu_argv(ctx.settings, ctx.host, kernel_image=ctx.kernel_image, rootfs=ctx.rootfs_image)
        self._launch(argv)
        return ctx
```

Create `src/likedbg/stages/debugger.py`:

```python
"""Debugger stage: attach containerized gdb to the QEMU gdbstub."""

from __future__ import annotations

from collections.abc import Callable

from likedbg.errors import BuildError
from likedbg.gdbcmd import build_gdb_args
from likedbg.pipeline import PipelineContext


class DebuggerStage:
    name = "debugger"

    def __init__(self, *, ext: str, run_gdb: Callable[[list[str]], None], breakpoint: str | None) -> None:
        self._ext = ext
        self._run_gdb = run_gdb
        self._breakpoint = breakpoint

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.vmlinux is None:
            raise BuildError("no vmlinux in context", remedy="run the Build/Export stages first")
        args = build_gdb_args(ctx.host, vmlinux=ctx.vmlinux, ext=self._ext, breakpoint=self._breakpoint)
        self._run_gdb(args)
        return ctx
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_debuggee.py tests/test_stage_debugger.py -v && uv run mypy src/likedbg`
Expected: 2 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/debuggee.py src/likedbg/stages/debugger.py tests/test_stage_debuggee.py tests/test_stage_debugger.py
git commit -m "feat: Debuggee (native QEMU launch) + Debugger (gdb attach) stages"
```

---

### Task 7: `start_kernel` PoC (EMPIRICAL — run & observe)

> **Empirical de-risk gate.** Not mockable. Boots the already-built 6.6.30 arm64 kernel under native HVF QEMU and attaches gdb to hit `start_kernel`. Run on branch `feat/m1-live-boot`. The debugger gdb image needs gef/pwndbg (the legacy `.dockerfile_dbg` + `like_debugger_tool_install.sh`); build/modernize it as part of this task. Expect iteration; fold working invocations/fixes back and commit.

- [ ] **Step 1: Build the debugger image** (`docker build -f .dockerfile_dbg -t like_debugger:latest --build-arg USER=user .`). Modernize `.dockerfile_dbg` if the legacy one fails on the new base (it must provide `gdb-multiarch` + gef or pwndbg). Record changes.
- [ ] **Step 2: Export the artifacts** to the host: run the `ArtifactExporter` (or, for the PoC, a one-off `docker run -v likedbg_ksrc:/ksrc -v $PWD/artifacts:/out like_dbg_base cp ...`) so `artifacts/linux-6.6.30/{vmlinux,Image}` exist on the host.
- [ ] **Step 3: Launch native QEMU** on the host: `qemu-system-aarch64 -M virt -cpu host -accel hvf -m 2048 -smp 2 -kernel artifacts/linux-6.6.30/Image -append "console=ttyAMA0 nokaslr" -nographic -S -s` (no rootfs needed to reach `start_kernel`). Confirm it waits for gdb (`-S`) with the stub on `:1234`.
- [ ] **Step 4: Attach gdb from a container:** `docker run --rm -it -v $PWD/artifacts/linux-6.6.30:/io like_debugger gdb-multiarch -q /io/vmlinux -ex "set architecture aarch64" -ex "target remote host.docker.internal:1234" -ex "break start_kernel" -ex "continue"`. Confirm the breakpoint at `start_kernel` is HIT (gef/pwndbg shows the stop). **This is the PoC success criterion.**
- [ ] **Step 5: Record** the exact working QEMU + gdb invocations and any `host.docker.internal` reachability notes to `docs/superpowers/notes/2026-06-22-arm64-boot-bringup.md`; fold any code/Dockerfile fixes back (keeping unit tests green) and commit.

---

### Task 8: Boot-to-shell + interactive breakpoint = M1 EXIT GATE (EMPIRICAL)

> **Empirical exit gate.** Build a rootfs, boot the kernel to an interactive shell over the serial console under native HVF, attach gdb, and set/hit a breakpoint during normal operation — all wired into the tmux `Session`.

- [ ] **Step 1: Build the rootfs** via the `RootfsStage` (debootstrap arm64). If debootstrap in the privileged container needs colima tweaks, record them. Produces `artifacts/rootfs-arm64.img`.
- [ ] **Step 2: Boot with rootfs:** native QEMU with the `build_qemu_argv` output including the rootfs drive; confirm the guest boots to a login/shell on the serial console (root, no password).
- [ ] **Step 3: Interactive breakpoint:** with the session up, attach gdb and set a breakpoint on a syscall/function reachable from userspace (e.g. `__arm64_sys_getpid`), trigger it from the guest shell, and confirm the hit.
- [ ] **Step 4: tmux wiring:** drive the whole thing through the `Session` (control pane + debuggee pane running native QEMU + debugger pane running gdb) so `start_kgdb`-style one-command UX works for arm64.
- [ ] **Step 5: Record** the M1 exit-gate evidence (boot-to-shell transcript + interactive breakpoint hit) in the notes; fold fixes back; commit. **M1 is complete when this passes.**

---

## Self-Review

- **Spec coverage:** docker-context socket resolution (Task 1 ✓, Plan 2 follow-up); volume→host artifact export (Task 2 ✓, §4.6); typed QEMU argv builder incl. accel/mitigations/gdbstub/rootfs-inference (Task 3 ✓, §4.4); corrected gdb attach over `host.docker.internal` (Task 4 ✓); rootfs builder + `resolv.conf` fix (Task 5 ✓); Debuggee/Debugger launch stages (Task 6 ✓); `start_kernel` PoC (Task 7 ✓); boot-to-shell + interactive breakpoint = M1 exit gate (Task 8 ✓). In-container QEMU backend (x86_64/Linux) is deferred to M2 per the spec; the argv builder already supports it.
- **Placeholder scan:** Tasks 1–6 contain complete runnable code/tests. Tasks 7–8 are explicitly empirical (concrete commands + run-and-observe), not hidden placeholders.
- **Type consistency:** stages implement the `Stage` protocol; `build_qemu_argv`/`build_gdb_args` signatures match their callers in Task 6; `PipelineContext` fields (`kernel_image`/`vmlinux`/`rootfs_image`) are reused from Plan 1/2; `ArtifactExporter`/`RootfsStage`/`host_artifact_dir`/`rootfs_target` names are consistent across tasks and tests.

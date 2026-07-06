# Custom Modules (2b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build out-of-tree kernel modules against the running session's kernel and load them into the live Debuggee on command, feeding the 2a exploit loop and the crash detector.

**Architecture:** A deep `modules.py` seam (kbuilder-container `make -C <kernel_root> M=/mod modules` build + SSH `insmod`/`rmmod` over 2a's `guest.py`) + a boot-time `ModuleBuildStage` that stages each `custom_modules` `.ko` into the 2a Guest share (`exploit/modules/`) + a re-runnable `start_kgdb --insmod`/`--rmmod` command (host-side; `--insmod` builds-if-stale via its own kbuilder container, then loads over SSH — no tmux). Prebuilt `.ko`s pass through; a content-hash (`input_hash`) gates rebuilds; an original vuln-driver seed + crash PoC ships under `modules/`.

**Tech Stack:** Python 3.12, Pydantic v2, Docker (kbuilder image, clang cross), out-of-tree Kbuild (`obj-m`), system `ssh`/`scp` (2a), pytest, ruff, mypy `--strict`, uv.

## Global Constraints

- **dev stays local — never `git push`.** Work on `feat/custom-modules` off `dev`; merge locally at the end.
- Python **3.12**; all new code passes `uv run ruff check src tests`, `uv run ruff format --check src tests`, `uv run mypy`, `uv run pytest -q`.
- **ruff isort `force-single-line`**: ONE import per line, in `src/` AND `tests/`. Use `pathlib` (`.read_text()`/`.write_text()`), never bare `open()` (PTH). Plan code blocks are REFERENCE — split grouped imports + fix types when transcribing.
- mypy `--strict` on `src/likedbg` (bare `uv run mypy`). Annotate every new param/return.
- **`container.exec(...).output` is CRLF** (tty=True) — `.replace("\r\n", "\n")` before any anchored/regex/`==` parse of guest or container output (bit B3; will bite `insmod`/`dmesg`/`modinfo` parsing).
- **Module build reuses the kernel's toolchain env** so vermagic matches: `make -C <kernel_root> M=/mod modules <ARCH=..> <LLVM=1|CROSS_COMPILE=..> -j$(nproc)`, env from `BuildRecipe.env()` (build) / `resolve_toolchain(compiler, arch).make_vars` (use).
- **Kernel tree mounts READ-ONLY** at `/ksrc` (`VOLUME_MOUNT`); module source mounts RW at the fixed path `/mod`. Confirmed 2026-07-06: `make M=` against a RO fully-built tree succeeds and writes only into `/mod`; identical-path binds don't surface under colima.
- **Content hash, not mtime:** `hash_tree(src_dir).aggregate` (ignores `.ko/.o/.mod/.mod.c/Module.symvers/modules.order`) gates rebuilds.
- Constants: `KERNEL_VOLUME="likedbg_ksrc"`, `VOLUME_MOUNT="/ksrc"`, `KBUILDER_IMAGE="like_kbuilder_arm64:latest"` (clang-universal; `_arm64` is a legacy misnomer).
- `LikeDbgError(message, *, remedy=None)`; `main()` catches `LikeDbgError` → rc 1. New `ModuleError(LikeDbgError)`.
- Spec: `docs/superpowers/specs/2026-07-06-custom-modules-design.md`. ADR-0009. Glossary: CONTEXT.md (**Custom module**, **Module build**).
- **Out of scope (2c):** foreign-kernel adoption (bring-your-own `bzImage`/initramfs). No `--force`/vermagic override. 2b builds only the `.ko` (not the userspace exploit binary).

---

## File Structure

**New:**
- `src/likedbg/modules.py` — build/load seam (`ModuleError`, `build_module`, `module_name`, `stale`, `load`, `unload`)
- `src/likedbg/stages/module_build.py` — `ModuleBuildStage`
- `modules/README.md`, `modules/template/{Makefile,hello.c}`, `modules/lk01/{Makefile,lk01.c,expl.c,README.md}`
- Tests: `tests/test_modules.py`, `tests/test_stage_module_build.py`, `tests/test_cli_insmod.py`
- `configs/fragments/module-unload.config` (kconfig fragment)

**Modified:**
- `src/likedbg/cli.py` — `cmd_insmod`/`cmd_rmmod`, argparse (`--insmod`/`--rmmod`/`--force-unload`), dispatch, `ModuleBuildStage` in both pipeline builders + its import
- `configs/profiles/exploit-dev.toml` — add the fragment + `[[expect]] CONFIG_MODULE_FORCE_UNLOAD=y`
- `.gitignore` — module build litter under `modules/`
- `examples/c_kmod/` → `examples/legacy-intree/` (move, + a note)

**Branch setup (before Task 1):**
```bash
git checkout dev && git checkout -b feat/custom-modules
```

---

## Task 1: `modules.py` — `ModuleError` + `build_module`

**Files:** Create `src/likedbg/modules.py`, `tests/test_modules.py`

**Interfaces:**
- Produces: `ModuleError(LikeDbgError)`; `build_module(container, *, src_dir: Path, kernel_root: str, mount_source: str, env: dict[str, str], out_dir: Path, image: str, volume: str) -> Path` — runs `make -C <kernel_root> M=/mod modules <env> -j$(nproc)` in the kbuilder container (kernel tree RO at `/ksrc`, `src_dir` RW at `/mod`), copies the built `.ko` from `src_dir` to `out_dir`, returns the copied `.ko` path.
- Consumes: `ContainerService` (`run_detached`/`exec`/`stop`), `constants.VOLUME_MOUNT`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_modules.py
from pathlib import Path

from likedbg import modules
from likedbg.errors import ModuleError


class FakeExec:
    def __init__(self, exit_code=0, output=""):
        self.exit_code = exit_code
        self.output = output


class FakeContainer:
    """Records run_detached kwargs + exec commands; simulates the .ko appearing."""

    def __init__(self, *, make_rc=0):
        self.run_kwargs = None
        self.execs: list[str] = []
        self._make_rc = make_rc
        self.stopped = False

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return "CID"

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        return FakeExec(exit_code=0, output="")

    def stop(self, container):
        self.stopped = True


def test_build_module_runs_make_and_returns_ko(tmp_path):
    src = tmp_path / "lk01"
    src.mkdir()
    (src / "lk01.c").write_text("// vuln\n")
    (src / "Makefile").write_text("obj-m += lk01.o\n")
    # simulate kbuild producing the .ko in the source dir (the RW /mod bind maps to src)
    (src / "lk01.ko").write_bytes(b"ELFKO")
    out = tmp_path / "exploit" / "modules"
    c = FakeContainer()
    ko = modules.build_module(
        c, src_dir=src, kernel_root="/ksrc/linux-6.6.30-abc", mount_source="likedbg_ksrc",
        env={"ARCH": "arm64", "LLVM": "1"}, out_dir=out, image="like_kbuilder_arm64:latest",
        volume="likedbg_ksrc",
    )
    assert ko == out / "lk01.ko"
    assert ko.read_bytes() == b"ELFKO"
    # kernel tree RO at /ksrc, module RW at /mod
    vols = c.run_kwargs["volumes"]
    assert vols["likedbg_ksrc"] == {"bind": "/ksrc", "mode": "ro"}
    assert vols[str(src)] == {"bind": "/mod", "mode": "rw"}
    make = " ".join(c.execs)
    assert "make -C /ksrc/linux-6.6.30-abc M=/mod" in make
    assert "ARCH=arm64" in make and "LLVM=1" in make and "modules" in make
    assert c.stopped is True


def test_build_module_raises_when_no_ko(tmp_path):
    src = tmp_path / "brokenmod"
    src.mkdir()
    (src / "Makefile").write_text("obj-m += brokenmod.o\n")  # produces no .ko
    c = FakeContainer()
    try:
        modules.build_module(
            c, src_dir=src, kernel_root="/ksrc/x", mount_source="likedbg_ksrc",
            env={"ARCH": "arm64", "LLVM": "1"}, out_dir=tmp_path / "out",
            image="img", volume="likedbg_ksrc",
        )
        raise AssertionError("expected ModuleError")
    except ModuleError as e:
        assert "no .ko" in str(e).lower() or "produced" in str(e).lower()
```

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_modules.py -q`
Expected: FAIL — no module `likedbg.modules`.

- [ ] **Step 3: Implement**
```python
# src/likedbg/modules.py
"""Out-of-tree kernel module build + guest load/unload seam. The build runs `make -C <kernel_root>
M=/mod modules` in the kbuilder container (kernel tree RO at /ksrc, module source RW at /mod) with the
kernel's toolchain env so vermagic matches; loading rides 2a's guest.py (ssh insmod/rmmod). See ADR-0009."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from likedbg.constants import VOLUME_MOUNT
from likedbg.errors import ModuleError

_MOD_MOUNT = "/mod"


def _make_cmd(kernel_root: str, env: dict[str, str]) -> str:
    vars_ = " ".join(f"{k}={v}" for k, v in env.items())
    return f"make -C {kernel_root} M={_MOD_MOUNT} {vars_} -j$(nproc) modules".replace("  ", " ")


def build_module(
    container: Any,
    *,
    src_dir: Path,
    kernel_root: str,
    mount_source: str,
    env: dict[str, str],
    out_dir: Path,
    image: str,
    volume: str,
) -> Path:
    """Build the out-of-tree module in `src_dir` against `kernel_root`; copy its `.ko` to `out_dir`."""
    c = container.run_detached(
        image,
        volumes={
            mount_source: {"bind": VOLUME_MOUNT, "mode": "ro"},
            str(src_dir): {"bind": _MOD_MOUNT, "mode": "rw"},
        },
        detach=True,
        tty=True,
    )
    try:
        container.exec(c, _make_cmd(kernel_root, env))
    finally:
        container.stop(c)
    kos = sorted(src_dir.glob("*.ko"))
    if not kos:
        raise ModuleError(
            f"module build produced no .ko in {src_dir}",
            remedy="check the module's obj-m Makefile and the build output",
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / kos[0].name
    shutil.copy2(kos[0], dest)
    return dest
```
Add to `src/likedbg/errors.py` (next to the other subclasses, e.g. after `BuildError`):
```python
class ModuleError(LikeDbgError):
    """Failure building or (un)loading an out-of-tree kernel module."""
```

- [ ] **Step 4: Run + full suite**
Run: `uv run pytest tests/test_modules.py -q && uv run pytest -q && uv run mypy && uv run ruff check src tests`
Expected: green.

- [ ] **Step 5: Commit**
```bash
git add src/likedbg/modules.py src/likedbg/errors.py tests/test_modules.py
git commit -m "feat(modules): build_module (kbuilder out-of-tree make, RO tree, .ko copy-out)"
```

---

## Task 2: `modules.py` — `module_name`

**Files:** Modify `src/likedbg/modules.py`; Test `tests/test_modules.py`

**Interfaces:**
- Produces: `module_name(container, ko: Path, *, image: str) -> str` — the loadable module name, from `modinfo -F name` (run in a container), falling back to the `.ko` stem with `-`→`_`.

- [ ] **Step 1: Write the failing test**
```python
# add to tests/test_modules.py
def test_module_name_from_modinfo(tmp_path):
    ko = tmp_path / "my-mod.ko"
    ko.write_bytes(b"ELFKO")

    class C:
        def run_detached(self, image, **kw):
            return "CID"

        def exec(self, c, cmd, *, workdir=None):
            return FakeExec(output="my_mod\r\n")  # CRLF, as tty=True

        def stop(self, c):
            pass

    assert modules.module_name(C(), ko, image="img") == "my_mod"


def test_module_name_falls_back_to_stem(tmp_path):
    ko = tmp_path / "foo-bar.ko"
    ko.write_bytes(b"ELFKO")

    class C:
        def run_detached(self, image, **kw):
            return "CID"

        def exec(self, c, cmd, *, workdir=None):
            return FakeExec(output="")  # modinfo yielded nothing

        def stop(self, c):
            pass

    assert modules.module_name(C(), ko, image="img") == "foo_bar"
```

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_modules.py -k module_name -q`
Expected: FAIL — no `module_name`.

- [ ] **Step 3: Implement**
Add to `src/likedbg/modules.py`:
```python
def module_name(container: Any, ko: Path, *, image: str) -> str:
    """The loadable module name: `modinfo -F name`, else the .ko stem with `-`→`_`."""
    c = container.run_detached(
        image, volumes={str(ko.parent): {"bind": _MOD_MOUNT, "mode": "ro"}}, detach=True, tty=True
    )
    try:
        out = container.exec(c, f"modinfo -F name {_MOD_MOUNT}/{ko.name}").output
    finally:
        container.stop(c)
    name = out.replace("\r\n", "\n").strip()
    return name or ko.stem.replace("-", "_")
```

- [ ] **Step 4: Run + full suite**
Run: `uv run pytest tests/test_modules.py -q && uv run mypy && uv run ruff check src tests`
Expected: green.

- [ ] **Step 5: Commit**
```bash
git add src/likedbg/modules.py tests/test_modules.py
git commit -m "feat(modules): module_name via modinfo with -→_ stem fallback"
```

---

## Task 3: `modules.py` — `load` + `unload`

**Files:** Modify `src/likedbg/modules.py`; Test `tests/test_modules.py`

**Interfaces:**
- Consumes: `guest.GuestEndpoint`/`run`/`push` (2a).
- Produces:
  - `load(endpoint, ko, *, name, share_dir, share_mount, args="", reload=True, force_unload=False, client=_guest) -> GuestResult` — deliver (in-place if `ko` is under `share_dir`, else `scp` into `<mount>/modules/`), then `insmod`. When `reload` and the module is loaded, `rmmod` first; EBUSY → `ModuleError` (no duplicate `insmod`) unless `force_unload` (`rmmod -f`). `insmod` non-zero → `ModuleError` with the guest `dmesg` tail.
  - `unload(endpoint, name, *, force=False, client=_guest) -> GuestResult` — `rmmod [-f] <name>`; not-loaded is a no-op success.

- [ ] **Step 1: Write the failing test**
```python
# add to tests/test_modules.py
from likedbg.guest import GuestEndpoint


class FakeGuest:
    """Scriptable guest client mirroring likedbg.guest's module API."""

    def __init__(self):
        self.ran: list[str] = []
        self.pushed: list = []
        self._loaded = False
        self._rmmod_rc = 0
        self._rmmod_err = ""
        self._insmod_rc = 0

    def run(self, ep, cmd, **kw):
        self.ran.append(cmd)

        class R:
            rc = 0
            stdout = ""
            stderr = ""

        r = R()
        if cmd.startswith("test -d /sys/module/"):
            r.stdout = "Y" if self._loaded else "N"
        elif cmd.startswith("rmmod"):
            r.rc = self._rmmod_rc
            r.stderr = self._rmmod_err
        elif cmd.startswith("insmod"):
            r.rc = self._insmod_rc
        elif cmd.startswith("dmesg"):
            r.stdout = "some dmesg\n"
        return r

    def push(self, ep, local, remote, **kw):
        self.pushed.append((local, remote))


def _ep():
    return GuestEndpoint(host="127.0.0.1", port=2222, key=Path("/w/key"))


def test_load_in_place_insmods(tmp_path):
    share = tmp_path / "exploit"
    (share / "modules").mkdir(parents=True)
    ko = share / "modules" / "lk01.ko"
    ko.write_bytes(b"K")
    g = FakeGuest()
    modules.load(_ep(), ko, name="lk01", share_dir=share, share_mount="/mnt/exploit", client=g)
    assert not g.pushed  # under share → in place, no scp
    assert any(c == "insmod /mnt/exploit/modules/lk01.ko" for c in g.ran)


def test_load_scp_when_outside_share(tmp_path):
    share = tmp_path / "exploit"
    share.mkdir()
    ko = tmp_path / "elsewhere" / "lk01.ko"
    ko.parent.mkdir()
    ko.write_bytes(b"K")
    g = FakeGuest()
    modules.load(_ep(), ko, name="lk01", share_dir=share, share_mount="/mnt/exploit", client=g)
    assert g.pushed and g.pushed[0][1] == "/mnt/exploit/modules/lk01.ko"


def test_reload_busy_raises_and_keeps_old(tmp_path):
    share = tmp_path / "exploit"
    (share / "modules").mkdir(parents=True)
    ko = share / "modules" / "lk01.ko"
    ko.write_bytes(b"K")
    g = FakeGuest()
    g._loaded = True
    g._rmmod_rc = 1
    g._rmmod_err = "rmmod: ERROR: Module lk01 is in use"
    try:
        modules.load(_ep(), ko, name="lk01", share_dir=share, share_mount="/mnt/exploit",
                     reload=True, client=g)
        raise AssertionError("expected ModuleError")
    except ModuleError as e:
        assert "in use" in str(e).lower() or "busy" in str(e).lower()
    assert not any(c.startswith("insmod") for c in g.ran)  # no duplicate insmod


def test_reload_force_unload_uses_rmmod_f(tmp_path):
    share = tmp_path / "exploit"
    (share / "modules").mkdir(parents=True)
    ko = share / "modules" / "lk01.ko"
    ko.write_bytes(b"K")
    g = FakeGuest()
    g._loaded = True
    modules.load(_ep(), ko, name="lk01", share_dir=share, share_mount="/mnt/exploit",
                 reload=True, force_unload=True, client=g)
    assert any(c == "rmmod -f lk01" for c in g.ran)
    assert any(c.startswith("insmod") for c in g.ran)
```

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_modules.py -k "load or reload" -q`
Expected: FAIL — no `load`.

- [ ] **Step 3: Implement**
Add to `src/likedbg/modules.py` (add `import shlex` and `from likedbg import guest as _guest` up top, one per line):
```python
def _is_loaded(endpoint: object, name: str, client: Any) -> bool:
    r = client.run(endpoint, f"test -d /sys/module/{name} && echo Y || echo N")
    return r.stdout.replace("\r\n", "\n").strip() == "Y"


def load(
    endpoint: object,
    ko: Path,
    *,
    name: str,
    share_dir: Path,
    share_mount: str,
    args: str = "",
    reload: bool = True,
    force_unload: bool = False,
    client: Any = _guest,
) -> Any:
    """Deliver `ko` to the guest and insmod it; reload = rmmod-then-insmod (EBUSY aborts unless force)."""
    try:
        remote = f"{share_mount}/{ko.resolve().relative_to(share_dir.resolve())}"
    except ValueError:
        remote = f"{share_mount}/modules/{ko.name}"
        client.push(endpoint, ko, remote)
    if reload and _is_loaded(endpoint, name, client):
        rm = client.run(endpoint, f"rmmod {'-f ' if force_unload else ''}{name}".strip())
        if rm.rc != 0:
            raise ModuleError(
                f"could not unload {name}: {rm.stderr.strip() or 'in use'}",
                remedy="close the module's users / restart the session, or pass --force-unload",
            )
    ins = client.run(endpoint, f"insmod {shlex.quote(remote)} {args}".strip())
    if ins.rc != 0:
        dmesg = client.run(endpoint, "dmesg | tail -n 20").stdout.replace("\r\n", "\n")
        raise ModuleError(
            f"insmod {name} failed (rc={ins.rc}): {ins.stderr.strip()}\n{dmesg}",
            remedy="vermagic mismatch → rebuild the kernel to match, or build the module from source",
        )
    return ins


def unload(endpoint: object, name: str, *, force: bool = False, client: Any = _guest) -> Any:
    return client.run(endpoint, f"rmmod {'-f ' if force else ''}{name}".strip())
```

- [ ] **Step 4: Run + full suite**
Run: `uv run pytest tests/test_modules.py -q && uv run pytest -q && uv run mypy && uv run ruff check src tests`
Expected: green.

- [ ] **Step 5: Commit**
```bash
git add src/likedbg/modules.py tests/test_modules.py
git commit -m "feat(modules): load/unload over ssh (deliver+insmod, reload, EBUSY, force-unload)"
```

---

## Task 4: `modules.py` — `stale` (content-hash staleness)

**Files:** Modify `src/likedbg/modules.py`; Test `tests/test_modules.py`

**Interfaces:**
- Consumes: `input_hash.hash_tree`.
- Produces: `stale(src_dir: Path, ko: Path, kernel_label: str) -> bool` — True if `ko` is missing, or the sidecar `<ko>.hash` != `f"{kernel_label}:{hash_tree(src_dir).aggregate}"`. `record_hash(src_dir, ko, kernel_label) -> None` writes that sidecar.

- [ ] **Step 1: Write the failing test**
```python
# add to tests/test_modules.py
def test_stale_true_when_ko_missing(tmp_path):
    src = tmp_path / "m"
    src.mkdir()
    (src / "m.c").write_text("a\n")
    assert modules.stale(src, tmp_path / "m.ko", "linux-x") is True


def test_record_then_not_stale_until_source_or_label_changes(tmp_path):
    src = tmp_path / "m"
    src.mkdir()
    (src / "m.c").write_text("a\n")
    ko = tmp_path / "m.ko"
    ko.write_bytes(b"K")
    modules.record_hash(src, ko, "linux-x")
    assert modules.stale(src, ko, "linux-x") is False
    (src / "m.c").write_text("b\n")  # source changed
    assert modules.stale(src, ko, "linux-x") is True
    modules.record_hash(src, ko, "linux-x")
    assert modules.stale(src, ko, "linux-y") is True  # kernel label changed
```

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_modules.py -k stale -q`
Expected: FAIL — no `stale`.

- [ ] **Step 3: Implement**
Add to `src/likedbg/modules.py` (`from likedbg.input_hash import hash_tree` up top):
```python
def _stamp(src_dir: Path, kernel_label: str) -> str:
    return f"{kernel_label}:{hash_tree(src_dir).aggregate}"


def stale(src_dir: Path, ko: Path, kernel_label: str) -> bool:
    sidecar = ko.with_suffix(ko.suffix + ".hash")
    if not ko.is_file() or not sidecar.is_file():
        return True
    return sidecar.read_text().strip() != _stamp(src_dir, kernel_label)


def record_hash(src_dir: Path, ko: Path, kernel_label: str) -> None:
    ko.with_suffix(ko.suffix + ".hash").write_text(_stamp(src_dir, kernel_label))
```

- [ ] **Step 4: Run + full suite**
Run: `uv run pytest tests/test_modules.py -q && uv run mypy && uv run ruff check src tests`
Expected: green.

- [ ] **Step 5: Commit**
```bash
git add src/likedbg/modules.py tests/test_modules.py
git commit -m "feat(modules): content-hash staleness (input_hash sidecar, kernel-label keyed)"
```

---

## Task 5: `ModuleBuildStage`

**Files:** Create `src/likedbg/stages/module_build.py`, `tests/test_stage_module_build.py`

**Interfaces:**
- Consumes: `modules.build_module`/`stale`/`record_hash` (T1/T4), `cache.locations`, `PipelineContext`.
- Produces: `ModuleBuildStage(container, *, image, workspace, env, arch, volume)`; `name = "module-build"`; `should_skip(ctx)` True when `ctx.settings.build.custom_modules` is empty; `run(ctx)` builds/stages each entry into `workspace/<eff.share_dir>/modules/`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_stage_module_build.py
from pathlib import Path

from likedbg.config import Settings
from likedbg.stages.module_build import ModuleBuildStage


def _ctx(tmp_path, mods):
    from likedbg.pipeline import PipelineContext

    s = Settings().model_copy(update={"build": Settings().build.model_copy(update={"custom_modules": mods})})
    ctx = PipelineContext(settings=s, host=_host())
    ctx.build_label = "linux-6.6.30-abc"
    ctx.effective_debuggee = s.debuggee  # share_dir="exploit"
    return ctx


def _host():
    from likedbg.host_profile import HostProfile

    return HostProfile(
        os="darwin", host_arch="arm64", target_arch="arm64", accel="hvf",
        debuggee_mode="native-host", storage_mode="volume", gdbstub_addr="host.docker.internal",
    )


class FakeC:
    def run_detached(self, image, **kw):
        return "CID"

    def exec(self, c, cmd, *, workdir=None):
        class R:
            exit_code = 0
            output = ""

        return R()

    def stop(self, c):
        pass


def test_should_skip_when_no_modules(tmp_path):
    stage = ModuleBuildStage(FakeC(), image="img", workspace=tmp_path,
                             env={"ARCH": "arm64", "LLVM": "1"}, arch="arm64", volume="likedbg_ksrc")
    assert stage.should_skip(_ctx(tmp_path, ())) is True


def test_builds_and_stages_ko(tmp_path, monkeypatch):
    src = tmp_path / "modules" / "lk01"
    src.mkdir(parents=True)
    (src / "lk01.c").write_text("x\n")

    def fake_build(container, *, src_dir, kernel_root, mount_source, env, out_dir, image, volume):
        out_dir.mkdir(parents=True, exist_ok=True)
        ko = out_dir / "lk01.ko"
        ko.write_bytes(b"K")
        return ko

    monkeypatch.setattr("likedbg.modules.build_module", fake_build)
    stage = ModuleBuildStage(FakeC(), image="img", workspace=tmp_path,
                             env={"ARCH": "arm64", "LLVM": "1"}, arch="arm64", volume="likedbg_ksrc")
    ctx = _ctx(tmp_path, ("modules/lk01",))
    assert stage.should_skip(ctx) is False
    stage.run(ctx)
    assert (tmp_path / "exploit" / "modules" / "lk01.ko").is_file()


def test_prebuilt_ko_passthrough_copies_without_build(tmp_path, monkeypatch):
    ko_src = tmp_path / "prebuilt" / "given.ko"
    ko_src.parent.mkdir(parents=True)
    ko_src.write_bytes(b"PRE")

    def boom(*a, **k):
        raise AssertionError("must not build a prebuilt .ko")

    monkeypatch.setattr("likedbg.modules.build_module", boom)
    stage = ModuleBuildStage(FakeC(), image="img", workspace=tmp_path,
                             env={"ARCH": "arm64", "LLVM": "1"}, arch="arm64", volume="likedbg_ksrc")
    ctx = _ctx(tmp_path, ("prebuilt/given.ko",))
    stage.run(ctx)
    assert (tmp_path / "exploit" / "modules" / "given.ko").read_bytes() == b"PRE"
```

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_stage_module_build.py -q`
Expected: FAIL — no module `likedbg.stages.module_build`.

- [ ] **Step 3a: Add the shared `stage_module` helper to `src/likedbg/modules.py`**
This is the ONE build-or-stage routine, reused by both `ModuleBuildStage` (this task) and `cmd_insmod` (Task 6), per the pre-flight decision (`--insmod` rebuilds-if-stale). **Convention:** a source-dir entry's `.ko` is named after the dir (`obj-m += <dirname>.o`); the seeds follow it.
```python
def stage_module(
    container: Any,
    *,
    entry: Path,
    out_dir: Path,
    kernel_root: str,
    mount_source: str,
    env: dict[str, str],
    image: str,
    volume: str,
    kernel_label: str,
) -> Path:
    """Bring one custom_modules entry to a staged `.ko` in out_dir. Prebuilt `.ko` → copy it; source dir →
    build if the content hash (or kernel label) changed, else reuse the staged `.ko` (named after the dir)."""
    if entry.is_file() and entry.suffix == ".ko":
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / entry.name
        shutil.copy2(entry, dest)
        return dest
    ko = out_dir / f"{entry.name}.ko"
    if not stale(entry, ko, kernel_label):
        return ko
    built = build_module(
        container, src_dir=entry, kernel_root=kernel_root, mount_source=mount_source,
        env=env, out_dir=out_dir, image=image, volume=volume,
    )
    record_hash(entry, built, kernel_label)
    return built
```

- [ ] **Step 3b: Implement `ModuleBuildStage`**
```python
# src/likedbg/stages/module_build.py
"""Boot-time stage: build each build.custom_modules entry out-of-tree against the built kernel tree and
stage the .ko into the Guest share (exploit/modules/), so --insmod can load it live. See ADR-0009."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from likedbg import cache
from likedbg.constants import KERNEL_VOLUME
from likedbg.errors import BuildError
from likedbg.modules import stage_module
from likedbg.pipeline import PipelineContext


class ModuleBuildStage:
    name = "module-build"

    def __init__(
        self,
        container: Any,
        *,
        image: str,
        workspace: Path,
        env: dict[str, str],
        arch: str,
        volume: str = KERNEL_VOLUME,
    ) -> None:
        self._c = container
        self._image = image
        self._workspace = workspace
        self._env = env
        self._arch = arch
        self._volume = volume

    def should_skip(self, ctx: PipelineContext) -> bool:
        return not ctx.settings.build.custom_modules

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.build_label is None:
            raise BuildError("no build label in context", remedy="run the Build stage first")
        loc = cache.locations(
            ctx.build_label, arch=self._arch, storage_mode=ctx.host.storage_mode,
            workspace=self._workspace, volume=self._volume,
        )
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        out_dir = self._workspace / eff.share_dir / "modules"
        for rel in ctx.settings.build.custom_modules:
            stage_module(
                self._c, entry=self._workspace / rel, out_dir=out_dir, kernel_root=loc.kernel_root,
                mount_source=loc.gdb_mount_source, env=self._env, image=self._image,
                volume=self._volume, kernel_label=ctx.build_label,
            )
        return ctx
```
> `cache.locations(...)` returns `Locations(.kernel_root="/ksrc/<label>", .gdb_mount_source=<volume name | host artifacts/ksrc dir>)` — verified fields. The T5 test (Step 1) monkeypatches `likedbg.modules.build_module` (which `stage_module` calls) so the stage's build path is exercised without Docker.

- [ ] **Step 4: Run + full suite**
Run: `uv run pytest tests/test_stage_module_build.py -q && uv run pytest -q && uv run mypy && uv run ruff check src tests`
Expected: green.

- [ ] **Step 5: Commit**
```bash
git add src/likedbg/stages/module_build.py tests/test_stage_module_build.py
git commit -m "feat(module-build): ModuleBuildStage builds+stages custom_modules (.ko passthrough, hash-skip)"
```

---

## Task 6: CLI — `cmd_insmod` / `cmd_rmmod` + argparse + dispatch

**Files:** Modify `src/likedbg/cli.py`; Test `tests/test_cli_insmod.py`

**Interfaces:**
- Consumes: `modules` (T1-T4), `guest`, `cache`, `_resolve_run` pattern from `exploit.py`.
- Produces: `cmd_insmod(workspace, *, run_id, path, args, force_unload) -> int`; `cmd_rmmod(workspace, *, run_id, name, force_unload) -> int`; `--insmod PATH`/`--rmmod NAME`/`--force-unload` argparse + dispatch after `--run`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_cli_insmod.py
import json
import types
from pathlib import Path

import pytest

from likedbg import cli
from likedbg.errors import LikeDbgError


def _mkrun(tmp_path):
    runs = tmp_path / "artifacts" / "runs" / "r1"
    (runs / "logs").mkdir(parents=True)
    (runs / "run.json").write_text(json.dumps({
        "status": "launched", "build_label": "linux-6.6.30-x", "rootfs_label": "rootfs-arm64-x",
        "guest": {"ssh_host": "127.0.0.1", "ssh_port": 2222, "share_mount": "/mnt/exploit",
                  "share_dir": "exploit"},
    }))
    (runs / "host.json").write_text(json.dumps({"target_arch": "arm64", "storage_mode": "volume"}))
    reg = tmp_path / "artifacts" / "cache" / "rootfs"
    reg.mkdir(parents=True)
    (reg / "rootfs-arm64-x.json").write_text(json.dumps({
        "kind": "rootfs", "label": "rootfs-arm64-x", "key": "k", "version": "", "arch": "arm64",
        "paths": {"image_host": "/w/r.img", "ssh_key": "/w/r.img.id_ed25519"},
    }))
    (tmp_path / "exploit" / "modules").mkdir(parents=True)
    ko = tmp_path / "exploit" / "modules" / "lk01.ko"
    ko.write_bytes(b"K")
    return tmp_path, ko


def _patch_docker(monkeypatch):
    class FakeCS:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(cli, "ContainerService", FakeCS)
    monkeypatch.setattr(cli.docker_env, "make_client", lambda **k: object())
    monkeypatch.setattr(cli.docker_env, "resolve_docker_host", lambda **k: "unix://x")
    monkeypatch.setattr(cli, "resolve_toolchain", lambda comp, arch: types.SimpleNamespace(
        make_vars={"ARCH": arch, "LLVM": "1"}))
    monkeypatch.setattr(cli.cache, "locations", lambda *a, **k: types.SimpleNamespace(
        kernel_root="/ksrc/x", gdb_mount_source="likedbg_ksrc"))
    monkeypatch.setattr(cli, "load_config", lambda ws: types.SimpleNamespace(
        settings=types.SimpleNamespace(build=types.SimpleNamespace(compiler="clang", custom_modules=()))))
    monkeypatch.setattr(cli.guest, "wait_ready", lambda ep, **kw: True)


def test_cmd_insmod_stages_and_loads_prebuilt_ko(tmp_path, monkeypatch):
    ws, ko = _mkrun(tmp_path)
    _patch_docker(monkeypatch)
    captured: dict = {}

    def fake_stage(container, *, entry, out_dir, **kw):
        return entry if entry.suffix == ".ko" else out_dir / "lk01.ko"

    def fake_load(ep, ko_arg, *, name, share_dir, share_mount, args, reload, force_unload):
        captured.update(name=name, share_mount=share_mount, ko=ko_arg)
        return types.SimpleNamespace(rc=0, stdout="", stderr="")

    monkeypatch.setattr(cli, "stage_module", fake_stage)
    monkeypatch.setattr(cli.modules, "module_name", lambda c, k, *, image: "lk01")
    monkeypatch.setattr(cli.modules, "load", fake_load)
    rc = cli.cmd_insmod(ws, run_id="r1", path=str(ko), args="", force_unload=False)
    assert rc == 0
    assert captured["name"] == "lk01" and captured["share_mount"] == "/mnt/exploit"


def test_cmd_insmod_no_run_raises(tmp_path):
    with pytest.raises(LikeDbgError):
        cli.cmd_insmod(tmp_path, run_id="latest", path="", args="", force_unload=False)
```

> `cli` exposes `stage_module`/`ContainerService`/`docker_env`/`resolve_toolchain`/`cache`/`guest`/`modules`/`load_config` as module attributes (top-of-file imports), so `monkeypatch.setattr(cli, …)` patches them. Mirror `tests/test_cli.py`'s existing container-faking for the pipeline tests. `main()` catches `LikeDbgError` → rc 1, so the raise integrates.

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_cli_insmod.py -q`
Expected: FAIL — `cli` has no `cmd_insmod`.

- [ ] **Step 3: Implement**
Add to `cli.py` imports (one per line): `from likedbg import modules`, `from likedbg import guest`, `from likedbg import docker_env`, `from likedbg.container_service import ContainerService`, `from likedbg.toolchain import resolve_toolchain`, `from likedbg.modules import stage_module`, `from likedbg.errors import ModuleError` (or `from likedbg.errors import ModuleError` if not already). Per the pre-flight decision, `--insmod` **rebuilds-if-stale** — so it creates its own Docker `ContainerService` (no tmux) to build a stale source dir, then loads over SSH.
```python
def _guest_endpoint(workspace: Path, run_dir: Path, g: dict) -> guest.GuestEndpoint:
    rootfs_label = json.loads((run_dir / "run.json").read_text()).get("rootfs_label", "")
    key = cache.load_manifest(workspace, "rootfs", rootfs_label).paths.get("ssh_key", "")
    if not key:
        raise ModuleError("rootfs has no recorded SSH key", remedy="rebuild the rootfs")
    return guest.GuestEndpoint(host=g["ssh_host"], port=int(g["ssh_port"]), key=Path(key))


def cmd_insmod(workspace: Path, *, run_id: str, path: str, args: str, force_unload: bool) -> int:
    from likedbg.exploit import _resolve_run

    run_dir = _resolve_run(workspace, run_id)
    run_json = json.loads((run_dir / "run.json").read_text())
    g = run_json.get("guest")
    if not g:
        raise ModuleError("this run has no guest endpoint", remedy="boot with guest_net enabled")
    ep = _guest_endpoint(workspace, run_dir, g)
    share_dir = (workspace / g["share_dir"]).resolve()
    out_dir = share_dir / "modules"

    # build context (kernel tree + toolchain env) — reads the run's build label + host profile + config.
    build_label = run_json.get("build_label", "")
    host_json = json.loads((run_dir / "host.json").read_text())
    arch = host_json["target_arch"]
    storage_mode = host_json.get("storage_mode", "volume")
    compiler = load_config(workspace).settings.build.compiler
    env = dict(resolve_toolchain(compiler, arch).make_vars)
    loc = cache.locations(build_label, arch=arch, storage_mode=storage_mode, workspace=workspace)
    container = ContainerService(docker_env.make_client(docker_env.resolve_docker_host(env=os.environ)))

    # resolve the entries to stage (a PATH, else all configured custom_modules)
    if path:
        p = Path(path)
        entries = [p if p.is_absolute() else workspace / p]
    else:
        entries = [workspace / rel for rel in load_config(workspace).settings.build.custom_modules]
    if not entries:
        raise ModuleError("nothing to load", remedy="set custom_modules or pass a module path")

    kos = [
        stage_module(
            container, entry=e, out_dir=out_dir, kernel_root=loc.kernel_root,
            mount_source=loc.gdb_mount_source, env=env, image=KBUILDER_IMAGE,
            volume=KERNEL_VOLUME, kernel_label=build_label,
        )
        for e in entries
    ]
    if not guest.wait_ready(ep):
        raise ModuleError(
            f"guest not reachable at {ep.host}:{ep.port}",
            remedy="is a start_kgdb session booted and continued past start_kernel?",
        )
    for ko in kos:
        name = modules.module_name(container, ko, image=KBUILDER_IMAGE)
        res = modules.load(ep, ko, name=name, share_dir=share_dir, share_mount=g["share_mount"],
                           args=args, reload=True, force_unload=force_unload)
        print(f"[likedbg] loaded {name} (rc={res.rc}) — {g['share_mount']}/modules/{ko.name} "
              f"(add-symbol-file this .ko in gdb)")
    return 0


def cmd_rmmod(workspace: Path, *, run_id: str, name: str, force_unload: bool) -> int:
    from likedbg.exploit import _resolve_run

    run_dir = _resolve_run(workspace, run_id)
    g = json.loads((run_dir / "run.json").read_text()).get("guest")
    if not g:
        raise ModuleError("this run has no guest endpoint", remedy="boot with guest_net enabled")
    ep = _guest_endpoint(workspace, run_dir, g)
    if not guest.wait_ready(ep):
        raise ModuleError(f"guest not reachable at {ep.host}:{ep.port}", remedy="boot + continue the session")
    res = modules.unload(ep, name, force=force_unload)
    print(f"[likedbg] rmmod {name} (rc={res.rc})")
    return 0
```
> `stage_module` (Task 5) does the build-if-stale + prebuilt-`.ko` passthrough; a `.ko` PATH passes straight through, a stale source dir builds in the kbuilder container, a fresh one reuses the staged `.ko`. `cmd_insmod` therefore needs Docker (via its own `ContainerService`) but NOT tmux — so it still dispatches in the early host-command block. The T6 test monkeypatches `likedbg.modules.stage_module`, `likedbg.modules.module_name`, `likedbg.modules.load`, and `likedbg.guest.wait_ready`, and monkeypatches `cli.ContainerService`/`cli.docker_env` (or injects a fake) so no real Docker is needed in the unit test — mirror how `tests/test_cli.py` fakes the container for pipeline tests.

Argparse (next to `--run`, cli.py ~line 629-631):
```python
    parser.add_argument("--insmod", default="", metavar="MODULE")
    parser.add_argument("--rmmod", default="")
    parser.add_argument("--force-unload", action="store_true")
```
Dispatch (after the `--run` block, cli.py ~line 649):
```python
        if args.insmod:
            return cmd_insmod(workspace, run_id=args.run_id, path=args.insmod, args=args.args,
                              force_unload=args.force_unload)
        if args.rmmod:
            return cmd_rmmod(workspace, run_id=args.run_id, name=args.rmmod, force_unload=args.force_unload)
```

- [ ] **Step 4: Run + full suite**
Run: `uv run pytest tests/test_cli_insmod.py tests/test_cli.py -q && uv run mypy && uv run ruff check src tests`
Expected: green.

- [ ] **Step 5: Commit**
```bash
git add src/likedbg/cli.py tests/test_cli_insmod.py
git commit -m "feat(cli): --insmod/--rmmod (deliver+load over ssh, force-unload)"
```

---

## Task 7: Pipeline wiring — `ModuleBuildStage` in both builders

**Files:** Modify `src/likedbg/cli.py` (`build_pipeline`, `build_use_pipeline`); Test `tests/test_cli.py`

**Interfaces:**
- Produces: both pipeline builders insert `ModuleBuildStage(container, image=KBUILDER_IMAGE, workspace=workspace, env=..., arch=..., volume=kernel_volume)` after `ArtifactExporter`, before `DebuggeeStage`.

- [ ] **Step 1: Write the failing test**
```python
# add to tests/test_cli.py — mirror test_build_pipeline_includes_all_stage_names
def test_pipeline_has_module_build_before_debuggee(tmp_path):
    # ... same build_pipeline(...) setup as test_build_pipeline_includes_all_stage_names ...
    names = [s.name for s in pipe._stages]  # type: ignore[attr-defined]
    assert "module-build" in names
    assert names.index("module-build") < names.index("debuggee")
```

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_cli.py -k module_build_before_debuggee -q`
Expected: FAIL — no `module-build` stage.

- [ ] **Step 3: Implement**
Add the import (cli.py top): `from likedbg.stages.module_build import ModuleBuildStage`.
In `build_pipeline`, insert before the `DebuggeeStage(...)` line:
```python
            ModuleBuildStage(
                container, image=KBUILDER_IMAGE, workspace=workspace,
                env=build_recipe.env(), arch=build_recipe.arch, volume=kernel_volume,
            ),
```
`build_use_pipeline` has **no `build_recipe` and no settings** in scope (verified: its params are `host`, `workspace`, `kernel_volume`, `gdb_mount_source`, …). Thread the module env in as a new param. Add to `build_use_pipeline`'s signature: `module_env: dict[str, str]`, and insert before its `DebuggeeStage(...)` (cli.py ~line 363):
```python
            ModuleBuildStage(
                container, image=KBUILDER_IMAGE, workspace=workspace,
                env=module_env, arch=host.target_arch, volume=kernel_volume,
            ),
```
In the **caller `cmd_use`** (which HAS `use_settings` + `host`), compute + pass it at the `build_use_pipeline(...)` call (cli.py ~line 434):
```python
            module_env=dict(resolve_toolchain(use_settings.build.compiler, host.target_arch).make_vars),
```
Add `from likedbg.toolchain import resolve_toolchain` at cli.py top (verified: `toolchain.resolve_toolchain(compiler, arch) -> ToolchainEnv` with `.make_vars: dict[str, str]`; clang → `{"ARCH": arch, "LLVM": "1"}`, gcc → `{"ARCH": arch, "CROSS_COMPILE": …}`).

- [ ] **Step 4: Run + full suite**
Run: `uv run pytest tests/test_cli.py -q && uv run pytest -q && uv run mypy && uv run ruff check src tests`
Expected: green (both pipelines still build; new stage present).

- [ ] **Step 5: Commit**
```bash
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): wire ModuleBuildStage into build + use pipelines"
```

---

## Task 8: exploit-dev profile — `CONFIG_MODULE_FORCE_UNLOAD`

**Files:** Create `configs/fragments/module-unload.config`; Modify `configs/profiles/exploit-dev.toml`; Test `tests/test_debug_profiles.py`

**Interfaces:** Produces an exploit-dev `.config` with `CONFIG_MODULE_FORCE_UNLOAD=y` (enables `--force-unload`). Changes the exploit-dev cache key → one-time kernel rebuild (live gate).

- [ ] **Step 1: Write the failing test**
```python
# add to tests/test_debug_profiles.py — assert exploit-dev references the fragment + expects the symbol.
def test_exploit_dev_expects_force_unload(tmp_path):
    # load profiles from the repo configs (mirror this file's existing loader test);
    profs = load_profiles(Path("configs/profiles"))  # match the file's real load call
    exp = profs["exploit-dev"]
    assert any(e.symbol == "CONFIG_MODULE_FORCE_UNLOAD" and e.value == "y" for e in exp.expect)
    assert "configs/fragments/module-unload.config" in exp.fragments
```

- [ ] **Step 2: Run to verify it fails**
Run: `uv run pytest tests/test_debug_profiles.py -k force_unload -q`
Expected: FAIL.

- [ ] **Step 3: Implement**
`configs/fragments/module-unload.config`:
```
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_MODULE_FORCE_UNLOAD=y
```
In `configs/profiles/exploit-dev.toml`, add the fragment to `fragments = [...]`:
```toml
  "configs/fragments/module-unload.config",
```
and append an `[[expect]]` block:
```toml
[[expect]]
symbol = "CONFIG_MODULE_FORCE_UNLOAD"
value = "y"
severity = "hard"
```

- [ ] **Step 4: Run + full suite**
Run: `uv run pytest tests/test_debug_profiles.py -q && uv run pytest -q && uv run mypy && uv run ruff check src tests`
Expected: green.

- [ ] **Step 5: Commit**
```bash
git add configs/fragments/module-unload.config configs/profiles/exploit-dev.toml tests/test_debug_profiles.py
git commit -m "feat(profile): exploit-dev enables CONFIG_MODULE_FORCE_UNLOAD (for --force-unload)"
```

---

## Task 9: Seeds — template + LK01 driver + PoC + gitignore + retire legacy

**Files:** Create `modules/README.md`, `modules/template/{Makefile,hello.c}`, `modules/lk01/{Makefile,lk01.c,expl.c,README.md}`; Modify `.gitignore`; Move `examples/c_kmod/` → `examples/legacy-intree/`

**This task ships source seeds — no unit test; verify with `git`/`make -n` sanity + suite stays green.**

- [ ] **Step 1: obj-m template**
`modules/template/Makefile`:
```makefile
obj-m += hello.o
KDIR ?= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```
`modules/template/hello.c`:
```c
#include <linux/module.h>
#include <linux/kernel.h>
static int __init hello_init(void) { pr_info("likedbg: hello loaded\n"); return 0; }
static void __exit hello_exit(void) { pr_info("likedbg: hello unloaded\n"); }
module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("like-dbg out-of-tree module template");
```

- [ ] **Step 2: LK01 original vuln driver + crash PoC**
`modules/lk01/Makefile` (mirror the template, `obj-m += lk01.o`).
`modules/lk01/lk01.c` — an original `/dev/lk01` misc char device whose `ioctl` (cmd `LK01_COPY`) does an **unchecked** `copy_from_user(kbuf, arg.ptr, arg.len)` into a fixed `char kbuf[64]` on the stack (a deliberate overflow when `arg.len > 64`). Register via `misc_register`; `MODULE_LICENSE("GPL")`. Keep it ~60 lines, self-contained, no external headers beyond `linux/*`. Document the bug in a header comment.
`modules/lk01/expl.c` — a **crash-triggering PoC**: `open("/dev/lk01")`, build an `ioctl` arg with `len = 4096` and a large user buffer, `ioctl(fd, LK01_COPY, &arg)` → kernel stack overflow → panic. Prints progress; documented as the starting point for a real exploit (not an LPE).
`modules/lk01/README.md` — documents the bug, the loop (`--insmod ./modules/lk01` → build the PoC → `--run ./exploit/lk01_expl`), and the **PoC cross-compile one-liner** (static, guest arch), e.g.:
```bash
# arm64 guest (from the repo root); adjust --target for x86_64:
docker run --rm -v "$PWD/modules/lk01:/m:ro" -v "$PWD/exploit:/o:rw" like_kbuilder_arm64:latest \
  clang --target=aarch64-linux-gnu -static -o /o/lk01_expl /m/expl.c
```

- [ ] **Step 3: modules/README.md** — documents the out-of-tree flow, `custom_modules`, `--insmod`/`--rmmod`/`--force-unload`, the template, and the lk01 demo.

- [ ] **Step 4: .gitignore** — append:
```gitignore
# out-of-tree module build litter (keep sources + READMEs)
modules/**/*.ko
modules/**/*.o
modules/**/*.mod
modules/**/*.mod.c
modules/**/.*.cmd
modules/**/Module.symvers
modules/**/modules.order
```

- [ ] **Step 5: Retire the legacy in-tree examples**
```bash
git mv examples/c_kmod examples/legacy-intree
```
Add a one-line note at the top of `examples/legacy-intree/README.md`: "Legacy in-tree module injection (pre-2b). Out-of-tree modules now live in `modules/` (see 2b / ADR-0009)."

- [ ] **Step 6: Sanity + commit**
Run: `make -n -C modules/template KDIR=/tmp 2>/dev/null || true` (parses); `git check-ignore modules/lk01/lk01.ko && echo ignored`; `uv run pytest -q` (unchanged, green).
```bash
git add modules/ .gitignore examples/
git commit -m "feat(modules): obj-m template + original LK01 vuln driver + crash PoC + gitignore; retire in-tree c_kmod"
```

---

## Task 10: Live gate + full verification + roadmap

**This task is verification, not new code. Capture evidence.**

- [ ] **Step 1: Full local gate**
Run: `uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy && uv run pytest -q`
Record the pytest count.

- [ ] **Step 2: Rebuild images + kernel (the profile fragment changed exploit-dev's .config)**
```bash
just build-images
# exploit-dev now enables CONFIG_MODULE_FORCE_UNLOAD → a fresh kernel build happens on the next run
```

- [ ] **Step 3: Live gate — both arches (controller-driven; use the 2a live-gate method)**
Per arch (arm64 native; x86_64 in-container via a gitignored `configs/local.toml` `[general] arch="x86_64"`), in a `tmux` session:
1. `custom_modules = ["modules/lk01"]` (local.toml). `uv run ./start_kgdb` → `ModuleBuildStage` builds `lk01.ko` → `exploit/modules/lk01.ko` (assert `modinfo`/vermagic matches the kernel).
2. `continue` in gdb → guest to userspace; arm gdb (`break do_init_module`, or source `lx-symbols`).
3. **`--insmod`:** `uv run ./start_kgdb --insmod ./modules/lk01` → over SSH `insmod` succeeds; guest `lsmod`/`dmesg` shows `lk01`; gdb catches `lk01_init`.
4. **Reload:** edit `lk01.c` (bump a `pr_info`), `uv run ./start_kgdb` (rebuild stages a new `.ko`), `--insmod ./modules/lk01` → `rmmod`+`insmod` reload; then `--force-unload` path if a refcount is held.
5. **Exploit → crash:** compile the PoC per `modules/lk01/README.md` → `uv run ./start_kgdb --run ./exploit/lk01_expl` → kernel panic → B3 auto-produces `crash.json`/`crash.md`, `run.json` status `crashed`, symbolized backtrace into the driver.

Record a transcript under `docs/superpowers/notes/2026-07-06-custom-modules-live.md`.

- [ ] **Step 2b: systematic-debugging if the gate trips**
Risk spots (spec §9): RO-tree `make M=` on x86_64; vermagic match on x86_64 (clang); the RW `/mod` mount under the colima share; `modinfo` CRLF; module name `-`→`_` for `rmmod`. Use `superpowers:systematic-debugging` (root cause before fixes).

- [ ] **Step 3: Roadmap + finish**
Update `docs/superpowers/ROADMAP.md` §D: mark **B6 part 2 (2b `feat/custom-modules`)** DONE + live-gated; note **2c (foreign-kernel / CTF adopt)** is next. Commit.
Then `superpowers:finishing-a-development-branch` → merge `feat/custom-modules` into `dev` **locally**, delete the branch.

---

## Self-Review (completed at authoring)

**Spec coverage:** §2 goals → T1 (build_module), T3 (load/reload/force-unload), T5 (build-at-boot stage + prebuilt passthrough), T6 (--insmod/--rmmod), T4 (content-hash), T8 (force-unload config), T9 (seeds); §3 decisions 1-7 → T1/T3/T4/T5/T6 + T7 (pipeline) + T8; §4 architecture → T1-T7 (modules.py, stage, cli) + T8 (profile) + T9 (seeds); §5 data flow → T5→T6→(2a --run); §6 --insmod semantics/errors → T3/T6 (ModuleError, EBUSY, dmesg, no-run, guest_net=false); §7 testing → each task's tests + T10 live gate; §8 docs → committed (ADR-0009, CONTEXT.md); ROADMAP → T10. No gaps.

**Placeholder scan:** every code step carries real code; the "reuse existing test harness" notes (T6/T7/T8) point at concrete existing fixtures (`test_build_pipeline_includes_all_stage_names`, `cmd_run`/`cmd_analyze_crash` tests, the profile loader test). T5's `cache.locations` field-name note and T7's `resolve_toolchain` import-path note flag the two spots the implementer must confirm against the real code.

**Type consistency:** `build_module(container, *, src_dir, kernel_root, mount_source, env, out_dir, image, volume) -> Path`; `module_name(container, ko, *, image) -> str`; `stale(src_dir, ko, kernel_label) -> bool` / `record_hash(...)`; `load(endpoint, ko, *, name, share_dir, share_mount, args, reload, force_unload, client) -> GuestResult`; `unload(endpoint, name, *, force, client)`; `ModuleBuildStage(container, *, image, workspace, env, arch, volume)` with `name="module-build"`; `cmd_insmod(workspace, *, run_id, path, args, force_unload)` / `cmd_rmmod(workspace, *, run_id, name, force_unload)` — used identically across producer/consumer tasks.
```

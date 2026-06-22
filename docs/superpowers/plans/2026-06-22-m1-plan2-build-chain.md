# M1 Plan 2 — Build Chain & Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `likedbg` pipeline able to download, unpack (case-safely), and build a modern Linux kernel — wiring the Download/Unpack/Build stages onto the typed core from Plan 1, plus a one-command host bootstrap and modern builder images.

**Architecture:** New `likedbg.stages` subpackage holds the three concrete `Stage` implementations, each consuming `PipelineContext`/`Settings`/`HostProfile` from Plan 1 and side-effecting only through injected `ContainerService` (build/exec) and small injectable seams (downloader, unpacker). A `likedbg.toolchain` registry maps compiler+arch → build env (clang universal cross is the default). A `likedbg.bootstrap` prerequisite-checker has pure logic behind injectable probes; `scripts/bootstrap.sh` + a `justfile` do the side-effecting install. Modern `.dockerfile_base`/`.dockerfile_kbuilder` carry current clang/LLVM. The actual kernel build is validated live in the final task.

**Tech Stack:** Python 3.12, Pydantic, docker-py (via `ContainerService`), uv, ruff, mypy --strict, pytest; clang/LLVM cross-compilation; kconfig fragments + `merge_config.sh`; colima + QEMU + `tonistiigi/binfmt` on the host.

## Global Constraints

- Branching: `main` untouched. Work on feature branch `feat/m1-build-chain` forked from `dev`, merged back into `dev` after the final review. (Plan 1 is already merged on `dev`.)
- Package boundary: new code under `src/likedbg/` (incl. new `src/likedbg/stages/`); tests under `tests/`. Do NOT modify legacy flat `src/*.py`. Legacy is quarantined from ruff via the existing `force-exclude`.
- `mypy --strict` clean over `src/likedbg`; `ruff check .` and `ruff format --check .` clean repo-wide; line length 120. Run tools with `uv run`.
- Architecture is the first-class **arm64** target; x86_64 is compat. Default compiler is **clang** (universal cross via `ARCH=… LLVM=1`); gcc is opt-in.
- Stage classes implement the Plan 1 `Stage` protocol: attribute `name: str`, `run(ctx: PipelineContext) -> PipelineContext`, `should_skip(ctx: PipelineContext) -> bool`.
- Errors use the Plan 1 `LikeDbgError` subclasses with actionable `remedy=` ("what's wrong + how to fix"). Side-effects go behind injectable seams so tests need no network/Docker/kernel.
- Storage strategy from the spec §4.6: in `volume` mode the kernel tree lives in a Docker named volume; in `bind` mode on the workspace path. Unpack + build must honor `ctx.host.storage_mode`.

---

### Task 1: Toolchain registry

Map `(compiler, arch)` → the kernel `make` environment. Default clang/LLVM builds any arch from one toolchain; gcc uses per-arch cross prefixes.

**Files:**
- Create: `src/likedbg/toolchain.py`
- Create: `tests/test_toolchain.py`

**Interfaces:**
- Consumes: `likedbg.config.Arch`, `likedbg.errors.ConfigError`.
- Produces:
  - `ToolchainEnv` (frozen dataclass): `.make_vars: dict[str, str]` (e.g. `{"ARCH": "arm64", "LLVM": "1"}` or `{"ARCH": "arm64", "CROSS_COMPILE": "aarch64-linux-gnu-"}`), `.apt_packages: tuple[str, ...]` (packages the kbuilder image must install).
  - `resolve_toolchain(compiler: str, arch: Arch) -> ToolchainEnv` — `compiler` ∈ {`"clang"`, `"gcc"`}; raises `ConfigError` on unknown compiler. `KERNEL_ARCH` mapping: `arm64→"arm64"`, `x86_64→"x86_64"`. clang sets `LLVM=1` and no `CROSS_COMPILE`; gcc sets `CROSS_COMPILE` (`arm64→aarch64-linux-gnu-`, `x86_64→x86_64-linux-gnu-`) and apt packages `gcc-<triple>`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_toolchain.py`:

```python
import pytest

from likedbg.errors import ConfigError
from likedbg.toolchain import resolve_toolchain


def test_clang_arm64_is_llvm_no_cross_compile():
    env = resolve_toolchain("clang", "arm64")
    assert env.make_vars["ARCH"] == "arm64"
    assert env.make_vars["LLVM"] == "1"
    assert "CROSS_COMPILE" not in env.make_vars
    assert any("clang" in p or "llvm" in p for p in env.apt_packages)


def test_clang_x86_64_arch_name():
    env = resolve_toolchain("clang", "x86_64")
    assert env.make_vars["ARCH"] == "x86_64"
    assert env.make_vars["LLVM"] == "1"


def test_gcc_arm64_uses_cross_prefix_and_pkg():
    env = resolve_toolchain("gcc", "arm64")
    assert env.make_vars["CROSS_COMPILE"] == "aarch64-linux-gnu-"
    assert "LLVM" not in env.make_vars
    assert "gcc-aarch64-linux-gnu" in env.apt_packages


def test_unknown_compiler_raises():
    with pytest.raises(ConfigError):
        resolve_toolchain("tcc", "arm64")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_toolchain.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.toolchain'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/toolchain.py`:

```python
"""Toolchain registry: (compiler, arch) -> kernel make environment.

clang/LLVM is the default universal cross-compiler (one toolchain builds every
arch via ARCH=… LLVM=1); gcc uses per-arch cross prefixes. The registry is the
seam where pinned older toolchains slot in later.
"""

from __future__ import annotations

from dataclasses import dataclass

from likedbg.config import Arch
from likedbg.errors import ConfigError

_GCC_CROSS: dict[Arch, str] = {
    "arm64": "aarch64-linux-gnu-",
    "x86_64": "x86_64-linux-gnu-",
}

_CLANG_PACKAGES: tuple[str, ...] = ("clang", "lld", "llvm")


@dataclass(frozen=True)
class ToolchainEnv:
    make_vars: dict[str, str]
    apt_packages: tuple[str, ...]


def resolve_toolchain(compiler: str, arch: Arch) -> ToolchainEnv:
    if compiler == "clang":
        return ToolchainEnv(make_vars={"ARCH": arch, "LLVM": "1"}, apt_packages=_CLANG_PACKAGES)
    if compiler == "gcc":
        cross = _GCC_CROSS[arch]
        return ToolchainEnv(
            make_vars={"ARCH": arch, "CROSS_COMPILE": cross},
            apt_packages=(f"gcc-{cross.rstrip('-')}",),
        )
    raise ConfigError(
        f"unknown compiler: {compiler!r}",
        remedy="set [kernel_builder] compiler to 'clang' or 'gcc'",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_toolchain.py -v && uv run mypy src/likedbg`
Expected: 4 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/toolchain.py tests/test_toolchain.py
git commit -m "feat: toolchain registry (clang universal cross default, gcc opt-in)"
```

---

### Task 2: kconfig fragments

Composable config fragments merged onto `defconfig` via the kernel's `merge_config.sh` (replaces the legacy `-e/-d` arg strings).

**Files:**
- Create: `configs/fragments/debug.config`
- Create: `configs/fragments/no-kaslr.config`
- Create: `configs/fragments/generic.config`
- Create: `tests/test_fragments.py`

**Interfaces:**
- Produces: three fragment files, and a `generic` set = `[debug.config, no-kaslr.config, generic.config]` consumed by the Build stage (Task 7). Each line is a valid kconfig assignment (`CONFIG_X=y` / `# CONFIG_X is not set`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_fragments.py` (validates the fragments are well-formed kconfig):

```python
import re
from pathlib import Path

FRAG = Path(__file__).parent.parent / "configs" / "fragments"
LINE = re.compile(r"^(CONFIG_[A-Z0-9_]+=[ymn]|CONFIG_[A-Z0-9_]+=\"?.*\"?|# CONFIG_[A-Z0-9_]+ is not set)$")


def test_fragments_exist():
    for name in ("debug.config", "no-kaslr.config", "generic.config"):
        assert (FRAG / name).is_file(), name


def test_fragment_lines_are_valid_kconfig():
    for f in FRAG.glob("*.config"):
        for raw in f.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") and "CONFIG_" not in line:
                continue
            assert LINE.match(line), f"{f.name}: bad line {line!r}"


def test_debug_enables_debug_info_and_gdb_scripts():
    text = (FRAG / "debug.config").read_text()
    assert "CONFIG_DEBUG_INFO_DWARF4=y" in text
    assert "CONFIG_GDB_SCRIPTS=y" in text


def test_no_kaslr_disables_randomize_base():
    assert "# CONFIG_RANDOMIZE_BASE is not set" in (FRAG / "no-kaslr.config").read_text()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_fragments.py -v`
Expected: FAIL (files do not exist).

- [ ] **Step 3: Write the fragment files**

Create `configs/fragments/debug.config`:

```
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF4=y
CONFIG_FRAME_POINTER=y
CONFIG_GDB_SCRIPTS=y
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
# CONFIG_DEBUG_INFO_DWARF5 is not set
# CONFIG_DEBUG_INFO_REDUCED is not set
# CONFIG_DEBUG_INFO_BTF is not set
```

Create `configs/fragments/no-kaslr.config`:

```
# CONFIG_RANDOMIZE_BASE is not set
```

Create `configs/fragments/generic.config`:

```
CONFIG_IKCONFIG=y
CONFIG_IKCONFIG_PROC=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_fragments.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add configs/fragments tests/test_fragments.py
git commit -m "feat: kconfig fragments (debug, no-kaslr, generic)"
```

---

### Task 3: Download stage

Resolve the kernel version (mmp/tag/commit/latest) and download the source archive. Ports the legacy `KernelDownloader` onto the `Stage` protocol with an injectable HTTP seam.

**Files:**
- Create: `src/likedbg/stages/__init__.py`
- Create: `src/likedbg/stages/download.py`
- Create: `tests/test_stage_download.py`
- Modify: `src/likedbg/pipeline.py` (extend `PipelineContext` with build artifacts — see Step 3a)

**Interfaces:**
- Consumes: `PipelineContext`, `Settings.kernel_dl`, `likedbg.errors.DownloadError`.
- Produces:
  - `Fetcher = Callable[[str, Path], None]` (downloads URL → dest path).
  - `DownloadStage(fetcher: Fetcher, *, dl_dir: Path)` with `name = "download"`, `should_skip(ctx)` true if the archive already exists, `run(ctx)` setting `ctx.kernel_archive: Path`.
  - Module-level `resolve_version(cfg: KernelDlCfg) -> str` and `archive_url(version: str) -> str` (priority mmp > tag > commit; mmp uses the cdn `.tar.xz` URL, tag/commit use the torvalds snapshot `.tar.gz`).

- [ ] **Step 1: Add build-artifact fields to PipelineContext (Step 3a)**

Modify `src/likedbg/pipeline.py` — add two fields to the `PipelineContext` dataclass after `rootfs_image`:

```python
    vmlinux: Path | None = None
    kernel_image: Path | None = None
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_stage_download.py`:

```python
from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.stages.download import DownloadStage
from likedbg.stages.download import archive_url
from likedbg.stages.download import resolve_version
from likedbg.pipeline import PipelineContext


def _ctx(tmp_path, **dl):
    settings = Settings.model_validate({"kernel_dl": dl})
    host = HostProfile(os="linux", host_arch="arm64", accel="tcg", debuggee_mode="in-container",
                       storage_mode="bind", gdbstub_addr="localhost", ssh_addr="localhost")
    return PipelineContext(settings=settings, host=host)


def test_resolve_version_priority_mmp_over_tag():
    from likedbg.config import KernelDlCfg
    assert resolve_version(KernelDlCfg(mmp="6.6.30", tag="6.6")) == "6.6.30"


def test_archive_url_mmp_uses_cdn_xz():
    url = archive_url("6.6.30")
    assert url.endswith("linux-6.6.30.tar.xz")
    assert "cdn.kernel.org" in url


def test_download_runs_fetcher_and_sets_archive(tmp_path):
    calls = []
    stage = DownloadStage(lambda url, dest: calls.append((url, dest)) or dest.write_bytes(b"x"),
                          dl_dir=tmp_path)
    ctx = _ctx(tmp_path, tag="6.6")
    out = stage.run(ctx)
    assert out.kernel_archive is not None and out.kernel_archive.exists()
    assert len(calls) == 1


def test_download_skips_when_archive_present(tmp_path):
    stage = DownloadStage(lambda url, dest: None, dl_dir=tmp_path)
    ctx = _ctx(tmp_path, tag="6.6")
    (tmp_path / "linux-6.6.tar.gz").write_bytes(b"x")
    assert stage.should_skip(ctx) is True
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_download.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.stages'`.

- [ ] **Step 4: Write the implementation**

Create `src/likedbg/stages/__init__.py`:

```python
"""Concrete pipeline stages."""
```

Create `src/likedbg/stages/download.py`:

```python
"""Download stage: resolve a kernel version and fetch its source archive."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from likedbg.config import KernelDlCfg
from likedbg.errors import DownloadError
from likedbg.pipeline import PipelineContext

Fetcher = Callable[[str, Path], None]

_SNAPSHOT = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-"
_CDN = "https://cdn.kernel.org/pub/linux/kernel/v{major}.x/linux-{mmp}.tar.xz"


def resolve_version(cfg: KernelDlCfg) -> str:
    if cfg.mmp:
        return cfg.mmp
    if cfg.tag:
        return cfg.tag
    if cfg.commit:
        return cfg.commit
    raise DownloadError(
        "no kernel version specified",
        remedy="set [kernel_dl] mmp, tag, or commit in your .ini",
    )


def archive_url(version: str) -> str:
    parts = version.split(".")
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        return _CDN.format(major=parts[0], mmp=version)
    return f"{_SNAPSHOT}{version}.tar.gz"


def _archive_name(version: str) -> str:
    return f"linux-{version}.tar.{'xz' if archive_url(version).endswith('xz') else 'gz'}"


class DownloadStage:
    name = "download"

    def __init__(self, fetcher: Fetcher, *, dl_dir: Path) -> None:
        self._fetch = fetcher
        self._dl_dir = dl_dir

    def _dest(self, ctx: PipelineContext) -> Path:
        return self._dl_dir / _archive_name(resolve_version(ctx.settings.kernel_dl))

    def should_skip(self, ctx: PipelineContext) -> bool:
        return self._dest(ctx).exists()

    def run(self, ctx: PipelineContext) -> PipelineContext:
        self._dl_dir.mkdir(parents=True, exist_ok=True)
        version = resolve_version(ctx.settings.kernel_dl)
        dest = self._dest(ctx)
        self._fetch(archive_url(version), dest)
        ctx.kernel_archive = dest
        return ctx
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_download.py -v && uv run mypy src/likedbg`
Expected: 4 passed; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/stages tests/test_stage_download.py src/likedbg/pipeline.py
git commit -m "feat: Download stage (version resolve + fetch) on the Stage protocol"
```

---

### Task 4: Unpack stage (storage-aware)

Unpack the archive into case-safe storage: in `bind` mode onto the workspace path; in `volume` mode into a Docker named volume (so APFS case-insensitivity never corrupts the tree). Unpacking runs **inside a container** for consistency.

**Files:**
- Create: `src/likedbg/stages/unpack.py`
- Create: `tests/test_stage_unpack.py`

**Interfaces:**
- Consumes: `PipelineContext` (`ctx.kernel_archive`, `ctx.host.storage_mode`), `ContainerService`, `likedbg.errors.UnpackError`.
- Produces:
  - `UnpackStage(container: ContainerService, *, kernel_volume: str, workspace: Path)` with `name = "unpack"`, `should_skip(ctx)` false (idempotent re-unpack is cheap to check via marker), `run(ctx)` extracting into the storage location and setting `ctx.kernel_root: Path` (a container-side path under `/io` or the volume mount).
  - `kernel_root_path(ctx, *, mount: str) -> Path` — the container-side kernel root, `<mount>/<archive-stem>`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_stage_unpack.py`:

```python
from pathlib import Path
from types import SimpleNamespace

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.unpack import UnpackStage


class FakeContainerService(ContainerService):
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


def _ctx(storage_mode, tmp_path):
    host = HostProfile(os="darwin", host_arch="arm64", accel="hvf", debuggee_mode="native-host",
                       storage_mode=storage_mode, gdbstub_addr="host.docker.internal", ssh_addr="host.docker.internal")
    ctx = PipelineContext(settings=Settings(), host=host)
    ctx.kernel_archive = tmp_path / "linux-6.6.tar.gz"
    ctx.kernel_archive.write_bytes(b"x")
    return ctx


def test_volume_mode_mounts_named_volume(tmp_path):
    svc = FakeContainerService()
    UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("volume", tmp_path))
    mounts = str(svc.run_kwargs["volumes"])
    assert "likedbg_ksrc" in mounts


def test_extract_command_issued_and_kernel_root_set(tmp_path):
    svc = FakeContainerService()
    out = UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("bind", tmp_path))
    assert any("tar" in c for c in svc.execs)
    assert out.kernel_root is not None and "linux-6.6" in str(out.kernel_root)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_unpack.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.stages.unpack'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/stages/unpack.py`:

```python
"""Unpack stage: extract the kernel archive into case-safe storage, in-container."""

from __future__ import annotations

from pathlib import Path

from likedbg.container_service import ContainerService
from likedbg.pipeline import PipelineContext

_MOUNT = "/io"
_VOLUME_MOUNT = "/ksrc"
_BASE_IMAGE = "like_dbg_base"


def _archive_stem(archive: Path) -> str:
    # linux-6.6.tar.gz -> linux-6.6
    return archive.name.split(".tar.")[0]


def kernel_root_path(ctx: PipelineContext, *, mount: str) -> Path:
    assert ctx.kernel_archive is not None
    return Path(mount) / _archive_stem(ctx.kernel_archive)


class UnpackStage:
    name = "unpack"

    def __init__(self, container: ContainerService, *, kernel_volume: str, workspace: Path) -> None:
        self._c = container
        self._volume = kernel_volume
        self._workspace = workspace

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        assert ctx.kernel_archive is not None
        volume_mode = ctx.host.storage_mode == "volume"
        mount = _VOLUME_MOUNT if volume_mode else _MOUNT
        if volume_mode:
            volumes = {
                str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
                self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},
            }
            archive_in = f"{_MOUNT}/{ctx.kernel_archive.relative_to(self._workspace)}"
        else:
            volumes = {str(self._workspace): {"bind": _MOUNT, "mode": "rw"}}
            archive_in = f"{_MOUNT}/{ctx.kernel_archive.relative_to(self._workspace)}"
        container = self._c.run_detached(_BASE_IMAGE, volumes=volumes, detach=True, tty=True)
        try:
            self._c.exec(container, f"mkdir -p {mount}")
            self._c.exec(container, f"tar -C {mount} -xf {archive_in}")
        finally:
            self._c.stop(container)
        ctx.kernel_root = kernel_root_path(ctx, mount=mount)
        return ctx
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_unpack.py -v && uv run mypy src/likedbg`
Expected: 2 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/unpack.py tests/test_stage_unpack.py
git commit -m "feat: storage-aware Unpack stage (bind vs volume, in-container)"
```

---

### Task 5: Build stage

Configure and compile the kernel inside the kbuilder container via `ContainerService.exec`: mrproper → defconfig → merge fragments → `make -j` → set `vmlinux`/`Image` on the context. Command construction is unit-tested with a fake container.

**Files:**
- Create: `src/likedbg/stages/build.py`
- Create: `tests/test_stage_build.py`

**Interfaces:**
- Consumes: `PipelineContext` (`ctx.kernel_root`, `ctx.settings.general.arch`, `ctx.settings.kernel_builder.compiler`), `ContainerService`, `likedbg.toolchain.resolve_toolchain`, `likedbg.errors.BuildError`.
- Produces:
  - `BuildStage(container: ContainerService, *, kbuilder_image: str, fragments: list[str], workspace: Path, kernel_volume: str)` with `name = "build"`, `should_skip(ctx)` false, `run(ctx)` mounting storage per `ctx.host.storage_mode` (workspace at `/io`; the named volume at `/ksrc` in volume mode), executing the build, and setting `ctx.vmlinux` and `ctx.kernel_image`.
  - `make_command(env: dict[str, str], target: str) -> str` — assembles `make ARCH=… LLVM=1 -j$(nproc) <target>` from the toolchain env.

- [ ] **Step 1: Write the failing test**

Create `tests/test_stage_build.py`:

```python
from pathlib import Path
from types import SimpleNamespace

from likedbg.config import Settings
from likedbg.container_service import ContainerService
from likedbg.host_profile import HostProfile
from likedbg.pipeline import PipelineContext
from likedbg.stages.build import BuildStage
from likedbg.stages.build import make_command


class FakeC(ContainerService):
    def __init__(self):
        self.execs = []
        self.run_kwargs = None

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c1")

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append((cmd, workdir))
        return SimpleNamespace(exit_code=0, output="")

    def stop(self, container):
        pass


def _ctx(arch="arm64", compiler="clang", storage="bind"):
    s = Settings.model_validate({"general": {"arch": arch}, "kernel_builder": {"compiler": compiler}})
    host = HostProfile(os="linux", host_arch="arm64", accel="kvm", debuggee_mode="in-container",
                       storage_mode=storage, gdbstub_addr="localhost", ssh_addr="localhost")
    ctx = PipelineContext(settings=s, host=host)
    ctx.kernel_root = Path("/ksrc/linux-6.6" if storage == "volume" else "/io/linux-6.6")
    return ctx


def _stage(c, fragments=None):
    return BuildStage(c, kbuilder_image="like_kbuilder_arm64", fragments=fragments or [],
                      workspace=Path("/repo"), kernel_volume="likedbg_ksrc")


def test_make_command_includes_arch_llvm_and_nproc():
    cmd = make_command({"ARCH": "arm64", "LLVM": "1"}, "all")
    assert "ARCH=arm64" in cmd and "LLVM=1" in cmd and "-j$(nproc)" in cmd and cmd.endswith("all")


def test_build_runs_defconfig_merge_and_make():
    c = FakeC()
    _stage(c, ["configs/fragments/debug.config"]).run(_ctx())
    joined = "\n".join(cmd for cmd, _ in c.execs)
    assert "defconfig" in joined
    assert "merge_config.sh" in joined
    assert "make" in joined and "all" in joined


def test_build_sets_vmlinux_and_image_paths():
    out = _stage(FakeC()).run(_ctx("arm64"))
    assert out.vmlinux == Path("/io/linux-6.6/vmlinux")
    assert out.kernel_image == Path("/io/linux-6.6/arch/arm64/boot/Image")


def test_build_volume_mode_mounts_named_volume_and_workspace():
    c = FakeC()
    _stage(c).run(_ctx(storage="volume"))
    vols = str(c.run_kwargs["volumes"])
    assert "likedbg_ksrc" in vols and "/repo" in vols
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_stage_build.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.stages.build'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/stages/build.py`:

```python
"""Build stage: configure + compile the kernel in the kbuilder container."""

from __future__ import annotations

from pathlib import Path

from likedbg.container_service import ContainerService
from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext
from likedbg.toolchain import resolve_toolchain

_MOUNT = "/io"
_VOLUME_MOUNT = "/ksrc"


def make_command(env: dict[str, str], target: str) -> str:
    vars_str = " ".join(f"{k}={v}" for k, v in env.items())
    return f"make {vars_str} -j$(nproc) {target}".replace("  ", " ").strip()


def _image_path(kernel_root: Path, arch: str) -> Path:
    name = "bzImage" if arch == "x86_64" else "Image"
    return kernel_root / "arch" / arch / "boot" / name


class BuildStage:
    name = "build"

    def __init__(self, container: ContainerService, *, kbuilder_image: str, fragments: list[str],
                 workspace: Path, kernel_volume: str) -> None:
        self._c = container
        self._image = kbuilder_image
        self._fragments = fragments
        self._workspace = workspace
        self._volume = kernel_volume

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def _volumes(self, ctx: PipelineContext) -> dict[str, dict[str, str]]:
        # Mount the workspace at /io (for the kconfig fragments) and, in volume mode,
        # the named kernel-source volume at /ksrc (where Unpack put the tree).
        if ctx.host.storage_mode == "volume":
            return {
                str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
                self._volume: {"bind": _VOLUME_MOUNT, "mode": "rw"},
            }
        return {str(self._workspace): {"bind": _MOUNT, "mode": "rw"}}

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_root is None:
            raise BuildError("no kernel_root in context", remedy="run the Unpack stage first")
        arch = ctx.settings.general.arch
        env = resolve_toolchain(ctx.settings.kernel_builder.compiler, arch).make_vars
        root = ctx.kernel_root
        container = self._c.run_detached(self._image, volumes=self._volumes(ctx), detach=True, tty=True)
        try:
            self._c.exec(container, make_command(env, "mrproper"), workdir=str(root))
            self._c.exec(container, make_command(env, "defconfig"), workdir=str(root))
            if self._fragments:
                frags = " ".join(f"{_MOUNT}/{f}" for f in self._fragments)
                self._c.exec(
                    container,
                    f"./scripts/kconfig/merge_config.sh -m .config {frags} && {make_command(env, 'olddefconfig')}",
                    workdir=str(root),
                )
            self._c.exec(container, make_command(env, "all"), workdir=str(root))
        finally:
            self._c.stop(container)
        ctx.vmlinux = root / "vmlinux"
        ctx.kernel_image = _image_path(root, arch)
        return ctx
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_stage_build.py -v && uv run mypy src/likedbg`
Expected: 3 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/build.py tests/test_stage_build.py
git commit -m "feat: Build stage (defconfig + fragments + clang/LLVM make) via docker exec"
```

---

### Task 6: Bootstrap prerequisite-checker

Pure logic that reports which host prerequisites are present/missing with actionable remedies. Side-effecting installs live in the shell script (Task 7).

**Files:**
- Create: `src/likedbg/bootstrap.py`
- Create: `tests/test_bootstrap.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces:
  - `Prereq` (frozen dataclass): `.name: str`, `.ok: bool`, `.remedy: str | None`.
  - `BootstrapProbes` (frozen dataclass) of callables: `has(cmd: str) -> bool`, `colima_running() -> bool`, `binfmt_arm64() -> bool`.
  - `check_prerequisites(os_name: str, probes: BootstrapProbes) -> list[Prereq]` — on macOS requires `colima` (and running), `qemu-system-aarch64`, `uv`, and arm64 binfmt; on Linux requires `docker`, `uv`, binfmt. Each missing item carries a remedy.

- [ ] **Step 1: Write the failing test**

Create `tests/test_bootstrap.py`:

```python
from likedbg.bootstrap import BootstrapProbes
from likedbg.bootstrap import check_prerequisites


def _probes(present=(), colima=False, binfmt=False):
    return BootstrapProbes(
        has=lambda cmd: cmd in present,
        colima_running=lambda: colima,
        binfmt_arm64=lambda: binfmt,
    )


def test_macos_all_present_all_ok():
    p = _probes(present={"colima", "qemu-system-aarch64", "uv"}, colima=True, binfmt=True)
    results = check_prerequisites("darwin", p)
    assert all(r.ok for r in results)


def test_macos_missing_qemu_reports_remedy():
    p = _probes(present={"colima", "uv"}, colima=True, binfmt=True)
    results = check_prerequisites("darwin", p)
    qemu = next(r for r in results if "qemu" in r.name)
    assert qemu.ok is False and qemu.remedy and "brew" in qemu.remedy


def test_macos_colima_installed_but_not_running_is_not_ok():
    p = _probes(present={"colima", "qemu-system-aarch64", "uv"}, colima=False, binfmt=True)
    results = check_prerequisites("darwin", p)
    colima = next(r for r in results if r.name == "colima")
    assert colima.ok is False and colima.remedy and "colima start" in colima.remedy


def test_linux_requires_docker_not_colima():
    p = _probes(present={"docker", "uv"}, binfmt=True)
    names = {r.name for r in check_prerequisites("linux", p)}
    assert "docker" in names and "colima" not in names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_bootstrap.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.bootstrap'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/bootstrap.py`:

```python
"""Host prerequisite checks for the build/run environment (pure logic; installs
are done by scripts/bootstrap.sh). Each missing prerequisite carries a remedy."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Prereq:
    name: str
    ok: bool
    remedy: str | None


@dataclass(frozen=True)
class BootstrapProbes:
    has: Callable[[str], bool]
    colima_running: Callable[[], bool]
    binfmt_arm64: Callable[[], bool]


def check_prerequisites(os_name: str, probes: BootstrapProbes) -> list[Prereq]:
    results: list[Prereq] = []
    results.append(Prereq("uv", probes.has("uv"), None if probes.has("uv") else "install uv: https://docs.astral.sh/uv/"))
    if os_name == "darwin":
        colima_ok = probes.has("colima") and probes.colima_running()
        results.append(Prereq(
            "colima", colima_ok,
            None if colima_ok else ("brew install colima && colima start" if not probes.has("colima") else "colima start"),
        ))
        results.append(Prereq(
            "qemu-system-aarch64", probes.has("qemu-system-aarch64"),
            None if probes.has("qemu-system-aarch64") else "brew install qemu",
        ))
    else:
        results.append(Prereq("docker", probes.has("docker"), None if probes.has("docker") else "install Docker engine"))
    results.append(Prereq(
        "binfmt-arm64", probes.binfmt_arm64(),
        None if probes.binfmt_arm64() else "docker run --privileged --rm tonistiigi/binfmt --install all",
    ))
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_bootstrap.py -v && uv run mypy src/likedbg`
Expected: 4 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/bootstrap.py tests/test_bootstrap.py
git commit -m "feat: bootstrap prerequisite checker with actionable remedies"
```

---

### Task 7: Bootstrap script, justfile, and builder Dockerfiles (BRING-UP)

> **Bring-up task — partly empirical.** The Dockerfiles and the install script are written here with concrete, current content, but their *real* validation is Task 8 (a live kernel build). The reviewer judges the content's plausibility and the scripts' structure; "it builds a kernel" is proven in Task 8.

**Files:**
- Create: `scripts/bootstrap.sh`
- Create: `justfile`
- Modify: `.dockerfile_base`
- Modify: `.dockerfile_kbuilder`

**Interfaces:**
- Consumes: `likedbg.bootstrap.check_prerequisites` (the script calls `uv run python -m likedbg.bootstrap --check`, which Step 1 adds).

- [ ] **Step 1: Add a `__main__` check entrypoint to bootstrap.py**

Append to `src/likedbg/bootstrap.py`:

```python
def _real_probes() -> BootstrapProbes:
    import shutil
    import subprocess

    def colima_running() -> bool:
        out = subprocess.run(["colima", "status"], capture_output=True, text=True, check=False)
        return "running" in (out.stdout + out.stderr).lower()

    def binfmt_arm64() -> bool:
        return shutil.which("docker") is not None  # refined in Task 8 bring-up

    return BootstrapProbes(
        has=lambda cmd: shutil.which(cmd) is not None,
        colima_running=colima_running,
        binfmt_arm64=binfmt_arm64,
    )


def main() -> int:
    import platform

    results = check_prerequisites(platform.system().lower(), _real_probes())
    failed = [r for r in results if not r.ok]
    for r in results:
        mark = "ok" if r.ok else "MISSING"
        line = f"[{mark}] {r.name}"
        if r.remedy:
            line += f"  -> {r.remedy}"
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Verify the check entrypoint runs**

Run: `uv run python -m likedbg.bootstrap --check || true`
Expected: prints a `[ok]/[MISSING]` line per prerequisite (exit non-zero if any missing — that's fine on a fresh host).

- [ ] **Step 3: Write `scripts/bootstrap.sh`**

```bash
#!/usr/bin/env bash
# Idempotent host setup for LIKE-DBG. macOS: colima + qemu + binfmt + uv.
# Linux: docker + binfmt + uv. Re-running is safe.
set -euo pipefail

OS="$(uname -s)"
log() { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$1"; }

ensure_brew_pkg() { brew list "$1" >/dev/null 2>&1 || brew install "$1"; }

if [ "$OS" = "Darwin" ]; then
  command -v brew >/dev/null || { echo "Homebrew required: https://brew.sh"; exit 1; }
  ensure_brew_pkg colima
  ensure_brew_pkg qemu
  ensure_brew_pkg uv
  ensure_brew_pkg just
  if ! colima status 2>&1 | grep -qi running; then
    log "starting colima (vz, 4 CPU, 8GiB, 60GiB disk)"
    colima start --vm-type vz --cpu 4 --memory 8 --disk 60 --mount-type virtiofs
  fi
else
  command -v docker >/dev/null || { echo "Docker engine required"; exit 1; }
  command -v uv >/dev/null || { echo "Install uv: https://docs.astral.sh/uv/"; exit 1; }
fi

log "installing qemu binfmt handlers (for cross-arch rootfs/builds)"
docker run --privileged --rm tonistiigi/binfmt --install all >/dev/null

log "syncing python deps"
uv sync

log "prerequisite check:"
uv run python -m likedbg.bootstrap --check || true
log "done. If anything shows MISSING above, follow its '->' remedy."
```

Then `chmod +x scripts/bootstrap.sh`.

- [ ] **Step 4: Write `justfile`**

```just
# LIKE-DBG developer commands
bootstrap:
    ./scripts/bootstrap.sh

check:
    uv run python -m likedbg.bootstrap --check

test:
    uv run pytest -q

lint:
    uv run ruff check . && uv run ruff format --check . && uv run mypy src/likedbg
```

- [ ] **Step 5: Modernize `.dockerfile_base`**

Replace `.dockerfile_base` contents:

```dockerfile
FROM ubuntu:24.04
LABEL maintainer="Christopher Krah <admin@0x434b.dev>"
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG USER=user

RUN apt-get update && apt-get install -yq --no-install-recommends \
        sudo git wget curl file unzip xz-utils ca-certificates \
        python3 python3-pip build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    useradd -m -s /bin/bash "$USER" && \
    echo "$USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$USER

WORKDIR /io
```

- [ ] **Step 6: Modernize `.dockerfile_kbuilder`** (clang/LLVM cross + kernel build deps + rustup-ready)

Replace `.dockerfile_kbuilder` contents:

```dockerfile
FROM like_dbg_base:latest
LABEL maintainer="Christopher Krah <admin@0x434b.dev>"
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -yq --no-install-recommends \
        clang lld llvm \
        libncurses-dev libssl-dev libelf-dev bc flex bison cpio rsync ccache kmod && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Rust toolchain present but unused unless a build enables CONFIG_RUST.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal || true

WORKDIR /io
```

- [ ] **Step 7: Commit**

```bash
chmod +x scripts/bootstrap.sh
git add scripts/bootstrap.sh justfile .dockerfile_base .dockerfile_kbuilder src/likedbg/bootstrap.py
git commit -m "feat: host bootstrap (colima/qemu/binfmt/uv) + modern base/kbuilder images"
```

---

### Task 8: Live arm64 build validation (EMPIRICAL — run & observe)

> **Empirical gate.** This task is NOT mockable: it runs the real bootstrap and builds a real kernel on the M5. There is no failing-test-first cycle; the deliverable is an observed, working arm64 `vmlinux` + `Image`, with any command/Dockerfile adjustments discovered here folded back and committed. Expect iteration. This may take 20–40+ minutes and several GB.

**Steps (run, observe, adjust, record):**

- [ ] **Step 1: Bootstrap the host**

Run: `just bootstrap`
Expected: colima starts; `qemu`, `uv`, binfmt installed; the prerequisite check prints all `[ok]`. Record any MISSING + how you resolved it.

- [ ] **Step 2: Build the base + kbuilder images**

Run:
```bash
docker build -f .dockerfile_base  -t like_dbg_base:latest --build-arg USER=user .
docker build -f .dockerfile_kbuilder -t like_kbuilder_arm64:latest .
```
Expected: both images build. If a package name changed on Ubuntu 24.04 or clang errors, fix `.dockerfile_*` and re-run; record the change.

- [ ] **Step 3: Drive the pipeline to build an arm64 kernel**

Write a throwaway script `scripts/_poc_build.py` that wires `DownloadStage → UnpackStage → BuildStage` with a real `ContainerService(docker.from_env())`, a real `Fetcher` (`urllib.request.urlretrieve`), `Settings` for `arch=arm64`, `mmp=6.6.30`, `compiler=clang`, the `generic` fragment set, and `HostProfile.detect(...)`. Run it: `uv run python scripts/_poc_build.py`.
Expected: downloads 6.6.30, unpacks (volume mode on the case-insensitive Mac), and `make` produces `vmlinux` + `arch/arm64/boot/Image`. Record the actual `make`/`merge_config.sh` invocations that worked; if any stage command needed adjustment, fix the stage code (keeping its unit tests green) and re-commit.

- [ ] **Step 4: Confirm the artifacts**

Run (inside the kbuilder container or via the volume): `file vmlinux` (→ ELF, arm64) and `file arch/arm64/boot/Image` (→ Linux kernel ARM64 boot executable). Record sizes/paths.

- [ ] **Step 5: Record findings + commit any adjustments**

Append the working command transcript (image build, the three stage commands, artifact `file` output) to a new `docs/superpowers/notes/2026-06-22-arm64-build-bringup.md`. Commit the note plus any stage/Dockerfile fixes discovered:
```bash
git add -A
git commit -m "chore: arm64 build bring-up notes + fixes from live validation"
```

- [ ] **Step 6: Remove the throwaway PoC script**

```bash
git rm scripts/_poc_build.py
git commit -m "chore: drop throwaway PoC build script (logic lives in stages + Plan 3 assembly)"
```

---

## What this plan defers (Plan 3)

- The boot + native QEMU (HVF) launch + containerized gdb attach over `host.docker.internal`, and the **`start_kernel` breakpoint PoC** (the HVF/path/networking de-risk) — these need the debuggee/debugger code, so they open Plan 3.
- The rootfs builder, the typed QEMU argv builder + two debuggee backends, the Debugger stage, and the full boot-to-shell + interactive-breakpoint session = the M1 exit gate.
- A top-level assembly/CLI wiring the stages into the tmux `Session` (currently each PoC wires them ad hoc).

## Self-Review

- **Spec coverage:** modern base/kbuilder images (Task 7 ✓); clang universal cross toolchain registry (Task 1 ✓); kconfig fragments replacing arg-strings (Task 2 ✓); Download/Unpack/Build stages on the Stage protocol via ContainerService/docker-exec (Tasks 3–5 ✓); storage-aware unpack honoring §4.6 bind/volume (Task 4 ✓); one-command bootstrap + actionable diagnostics (Tasks 6–7 ✓); live arm64 build validation (Task 8 ✓). Boot/QEMU/gdb + rootfs + start_kernel PoC explicitly deferred to Plan 3.
- **Placeholder scan:** Tasks 1–6 contain complete runnable code/tests. Tasks 7–8 are explicitly flagged bring-up/empirical (concrete content + run-and-observe), not hidden placeholders.
- **Type consistency:** stages implement the Plan 1 `Stage` protocol (`name`/`run`/`should_skip`); `PipelineContext` is extended once (Task 3 Step 1) with `vmlinux`/`kernel_image`; `resolve_toolchain`/`ToolchainEnv`, `Fetcher`, `BootstrapProbes`/`Prereq` names match across tasks and tests.

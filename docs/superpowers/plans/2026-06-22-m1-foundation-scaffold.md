# M1 Plan 1 — Foundation Scaffold (tooling + typed core) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up modern Python tooling (uv + Python 3.12 + ruff + mypy) and the typed core
of the rework — `errors`, `config`, `host_profile`, `container_service`, `session`,
`pipeline` — as a new `likedbg` package, fully unit-tested and mypy-clean, without touching
the legacy `src/*.py` modules yet.

**Architecture:** The new code lives in a fresh package `src/likedbg/` alongside the legacy
flat modules (which stay until later plans port them). Every unit has injectable
dependencies (docker client, subprocess runner, detection probes) so it is testable with no
Docker/QEMU/colima/kernel present. Data flows `INI → Settings (Pydantic, validated) →
HostProfile → PipelineContext`, with side-effecting work behind `ContainerService` and
`Session`.

**Tech Stack:** Python 3.12, uv (project/deps), Pydantic v2 (config), docker-py (containers),
loguru (logging), pytest + pytest-cov (tests), ruff (lint+format), mypy --strict (types),
pre-commit (hooks).

## Global Constraints

- **Branching:** `main` stays untouched. All work integrates on `dev`. This plan runs on a
  feature branch `feat/m1-foundation` forked from `dev`, merged back into `dev` at the end.
  `dev → main` only at the very end of the whole rework.
- **Python:** `requires-python = ">=3.12"`. No use of `Date.now`-style nondeterminism in
  pure logic; detection side-effects go through injectable probes.
- **Typing:** `mypy --strict` must pass over `src/likedbg`. Full type hints on all public
  functions.
- **Formatting/lint:** `ruff format` + `ruff check` clean. Line length 120. `black` and
  `poetry` and `fabric` are removed from the project.
- **Diagnostics shape:** user-facing errors/warnings state **what's wrong + how to fix** —
  implemented via `LikeDbgError(message, remedy=...)`.
- **Package boundary:** new code only under `src/likedbg/`; tests under `tests/`. Do **not**
  modify legacy `src/*.py` in this plan.
- **Arch values:** architecture is `Literal["x86_64", "arm64"]`. Accel is
  `Literal["auto", "kvm", "hvf", "tcg"]`. Storage mode is `Literal["bind", "volume"]`.

---

### Task 1: Project tooling + package skeleton

Stand up uv/pyproject/ruff/mypy/pre-commit and an importable empty `likedbg` package. The
deliverable is a repo where `uv sync`, `uv run pytest`, `uv run ruff check`, and
`uv run mypy src/likedbg` all run green.

**Files:**
- Create: `pyproject.toml` (replace the existing Poetry one)
- Create: `src/likedbg/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/test_smoke.py`
- Create: `.pre-commit-config.yaml`
- Delete: `poetry.lock` (regenerated as `uv.lock`)

**Interfaces:**
- Consumes: nothing.
- Produces: importable package `likedbg` (version string `likedbg.__version__: str`); the
  toolchain commands used by every later task.

- [ ] **Step 1: Create the feature branch**

```bash
git checkout dev
git checkout -b feat/m1-foundation
```

- [ ] **Step 2: Write the failing smoke test**

Create `tests/__init__.py` (empty) and `tests/test_smoke.py`:

```python
import likedbg


def test_package_exposes_version():
    assert isinstance(likedbg.__version__, str)
    assert likedbg.__version__
```

- [ ] **Step 3: Write `pyproject.toml`**

```toml
[project]
name = "like-dbg"
version = "0.2.0"
description = "Fully containerized Linux kernel debugging environment"
readme = "README.md"
requires-python = ">=3.12"
license = { text = "MIT" }
dependencies = [
    "loguru>=0.7",
    "pydantic>=2.7",
    "docker>=7.1",
    "tqdm>=4.66",
    "requests>=2.32",
    "platformdirs>=4.2",
]

[dependency-groups]
dev = [
    "pytest>=8.2",
    "pytest-cov>=5.0",
    "ruff>=0.5",
    "mypy>=1.10",
    "pre-commit>=3.7",
    "types-requests",
    "types-tqdm",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/likedbg"]

[tool.ruff]
line-length = 120
target-version = "py312"
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "C4", "PTH", "TID", "PERF", "N", "UP", "B"]
ignore = ["E501"]

[tool.ruff.lint.isort]
force-single-line = true

[tool.mypy]
python_version = "3.12"
strict = true
files = ["src/likedbg"]

[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
addopts = "-q"
```

- [ ] **Step 4: Write the package init**

Create `src/likedbg/__init__.py`:

```python
"""LIKE-DBG — fully containerized Linux kernel debugging environment."""

__version__ = "0.2.0"
```

- [ ] **Step 5: Write the pre-commit config**

Create `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies: [pydantic]
        files: ^src/likedbg/
```

- [ ] **Step 6: Sync and verify the smoke test passes**

```bash
rm -f poetry.lock
uv sync
uv run pytest tests/test_smoke.py -v
```
Expected: `test_package_exposes_version PASSED`. A `uv.lock` is created.

- [ ] **Step 7: Verify lint + types are clean**

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy src/likedbg
```
Expected: all three exit 0 (no errors).

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml uv.lock src/likedbg/__init__.py tests/__init__.py tests/test_smoke.py .pre-commit-config.yaml
git rm --cached poetry.lock 2>/dev/null || true
git add -A
git commit -m "build: migrate to uv + ruff + mypy; add likedbg package skeleton"
```

---

### Task 2: `errors` — typed exception hierarchy with remedies

**Files:**
- Create: `src/likedbg/errors.py`
- Create: `tests/test_errors.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `LikeDbgError(message: str, *, remedy: str | None = None)` with attributes
    `.message: str`, `.remedy: str | None`, and `__str__` that appends `→ fix: <remedy>`
    when a remedy is set.
  - Subclasses (same constructor): `ConfigError`, `DownloadError`, `UnpackError`,
    `BuildError`, `RootfsError`, `HostCapabilityError`, `ContainerError`, `SessionError`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_errors.py`:

```python
import pytest

from likedbg.errors import ConfigError
from likedbg.errors import HostCapabilityError
from likedbg.errors import LikeDbgError


def test_message_only():
    err = LikeDbgError("bad thing")
    assert err.message == "bad thing"
    assert err.remedy is None
    assert str(err) == "bad thing"


def test_message_with_remedy_renders_fix_line():
    err = HostCapabilityError("no qemu", remedy="run 'just bootstrap'")
    assert err.remedy == "run 'just bootstrap'"
    assert str(err) == "no qemu\n  → fix: run 'just bootstrap'"


def test_subclasses_are_likedbgerror():
    assert issubclass(ConfigError, LikeDbgError)
    with pytest.raises(LikeDbgError):
        raise ConfigError("nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_errors.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.errors'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/errors.py`:

```python
"""Typed error hierarchy. Every error may carry an actionable remedy."""

from __future__ import annotations


class LikeDbgError(Exception):
    """Base class for all LIKE-DBG errors.

    `remedy` implements the "what's wrong + how to fix" diagnostics shape: when set, it is
    appended to the rendered message.
    """

    def __init__(self, message: str, *, remedy: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remedy = remedy

    def __str__(self) -> str:
        if self.remedy:
            return f"{self.message}\n  → fix: {self.remedy}"
        return self.message


class ConfigError(LikeDbgError):
    """Invalid or unparseable configuration."""


class DownloadError(LikeDbgError):
    """Failure to download a kernel archive."""


class UnpackError(LikeDbgError):
    """Failure to unpack a kernel archive."""


class BuildError(LikeDbgError):
    """Failure during kernel build."""


class RootfsError(LikeDbgError):
    """Failure building the root filesystem."""


class HostCapabilityError(LikeDbgError):
    """Host lacks a capability that an explicit request requires."""


class ContainerError(LikeDbgError):
    """Failure interacting with the container runtime."""


class SessionError(LikeDbgError):
    """Failure driving the tmux session."""
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_errors.py -v && uv run mypy src/likedbg`
Expected: 3 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/errors.py tests/test_errors.py
git commit -m "feat: typed error hierarchy with actionable remedies"
```

---

### Task 3: `config` — Pydantic settings + INI loader

Parse the existing two-tier INI (`system.ini` ◁ `user.ini` ◁ optional custom) into one
validated `Settings` tree, replacing the legacy `cfg_setter`. Includes the new keys
`toolchain`, `accel`, `workspace_dir`, `mac_storage`, `rust`.

**Files:**
- Create: `src/likedbg/config.py`
- Create: `tests/test_config.py`
- Create: `tests/fixtures/system.ini`
- Create: `tests/fixtures/user.ini`

**Interfaces:**
- Consumes: `likedbg.errors.ConfigError`.
- Produces:
  - Pydantic models: `GeneralCfg`, `KernelDlCfg`, `KernelBuilderCfg`, `RootfsCfg`,
    `DebuggeeCfg`, `DebuggerCfg`, and `Settings` with attributes `.general`, `.kernel_dl`,
    `.kernel_builder`, `.rootfs`, `.debuggee`, `.debugger`.
  - `Arch = Literal["x86_64", "arm64"]`, `Accel = Literal["auto", "kvm", "hvf", "tcg"]`,
    `MacStorage = Literal["auto", "bind", "volume"]`.
  - `load_settings(system_ini: Path, user_ini: Path, *, custom_ini: Path | None = None,
    overrides: dict[str, dict[str, str]] | None = None) -> Settings` — raises `ConfigError`
    on validation failure.

- [ ] **Step 1: Write the fixtures**

Create `tests/fixtures/system.ini`:

```ini
[general]
arch = x86_64
kernel_tag =
workspace_dir =
mac_storage = auto

[kernel_dl]
mmp =
tag =
commit =

[kernel_builder]
compiler = clang
toolchain = auto
mode = generic
rust = no
extra_args =
patch_dir =
custom_modules =

[rootfs]
distribution = bookworm
hostname = LIKE-DBG

[debuggee]
memory = 1024
smp = 1
kvm = no
gdb = yes
kaslr = no
smep = yes
smap = yes
kpti = yes
panic = halt
accel = auto

[debugger]
ext = gef
```

Create `tests/fixtures/user.ini`:

```ini
[general]
arch = arm64

[debuggee]
smep = no
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_config.py`:

```python
from pathlib import Path

import pytest

from likedbg.config import Settings
from likedbg.config import load_settings
from likedbg.errors import ConfigError

FIX = Path(__file__).parent / "fixtures"


def _load(**kw):
    return load_settings(FIX / "system.ini", FIX / "user.ini", **kw)


def test_user_overrides_system():
    s = _load()
    assert s.general.arch == "arm64"        # user.ini overrides system.ini
    assert s.debuggee.smep is False          # user.ini override
    assert s.debuggee.smap is True           # untouched system.ini value


def test_yes_no_become_bools():
    s = _load()
    assert s.debuggee.gdb is True
    assert s.kernel_builder.rust is False
    assert isinstance(s.debuggee.memory, int)


def test_blank_values_use_defaults_not_empty_string():
    s = _load()
    assert s.general.workspace_dir is None
    assert s.kernel_dl.tag is None


def test_cli_overrides_win_over_files():
    s = _load(overrides={"general": {"arch": "x86_64"}})
    assert s.general.arch == "x86_64"


def test_invalid_arch_raises_configerror():
    with pytest.raises(ConfigError):
        _load(overrides={"general": {"arch": "sparc"}})


def test_settings_is_immutable():
    s = _load()
    with pytest.raises(Exception):
        s.general.arch = "x86_64"  # type: ignore[misc]
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.config'`.

- [ ] **Step 4: Write the implementation**

Create `src/likedbg/config.py`:

```python
"""Typed configuration parsed from the two-tier INI files.

Precedence (lowest → highest): system.ini ◁ user.ini ◁ custom.ini ◁ overrides (CLI).
Blank INI values are treated as "unset" so model defaults apply.
"""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import ValidationError

from likedbg.errors import ConfigError

Arch = Literal["x86_64", "arm64"]
Accel = Literal["auto", "kvm", "hvf", "tcg"]
MacStorage = Literal["auto", "bind", "volume"]
BuildMode = Literal["generic", "syzkaller", "custom", "config"]
Compiler = Literal["clang", "gcc"]
Ext = Literal["gef", "pwndbg"]


class _Base(BaseModel):
    # Pydantic v2 lax coercion turns INI strings like "yes"/"no"/"1024" into bool/int,
    # so no custom validators are needed. Blank INI values are dropped by the loader, so
    # model defaults apply rather than empty strings.
    model_config = ConfigDict(frozen=True, extra="forbid")


class GeneralCfg(_Base):
    arch: Arch = "x86_64"
    kernel_tag: str = ""
    workspace_dir: str | None = None
    mac_storage: MacStorage = "auto"


class KernelDlCfg(_Base):
    mmp: str | None = None
    tag: str | None = None
    commit: str | None = None


class KernelBuilderCfg(_Base):
    compiler: Compiler = "clang"
    toolchain: str = "auto"
    mode: BuildMode = "generic"
    rust: bool = False
    extra_args: str | None = None
    patch_dir: str | None = None
    custom_modules: str | None = None


class RootfsCfg(_Base):
    distribution: str = "bookworm"
    hostname: str = "LIKE-DBG"


class DebuggeeCfg(_Base):
    memory: int = 1024
    smp: int = 1
    kvm: bool = False
    gdb: bool = True
    kaslr: bool = False
    smep: bool = True
    smap: bool = True
    kpti: bool = True
    panic: str = "halt"
    accel: Accel = "auto"


class DebuggerCfg(_Base):
    ext: Ext = "gef"


class Settings(_Base):
    general: GeneralCfg = GeneralCfg()
    kernel_dl: KernelDlCfg = KernelDlCfg()
    kernel_builder: KernelBuilderCfg = KernelBuilderCfg()
    rootfs: RootfsCfg = RootfsCfg()
    debuggee: DebuggeeCfg = DebuggeeCfg()
    debugger: DebuggerCfg = DebuggerCfg()


_SECTION_MODEL: dict[str, type[_Base]] = {
    "general": GeneralCfg,
    "kernel_dl": KernelDlCfg,
    "kernel_builder": KernelBuilderCfg,
    "rootfs": RootfsCfg,
    "debuggee": DebuggeeCfg,
    "debugger": DebuggerCfg,
}


def _layer(into: dict[str, dict[str, str]], cfg: configparser.ConfigParser) -> None:
    """Merge non-blank keys from a parsed INI onto the accumulator (later wins)."""
    for section in cfg.sections():
        for key, val in cfg[section].items():
            if val.strip() == "":
                continue  # blank == unset; keep the lower layer / default
            into.setdefault(section, {})[key] = val


def _read(path: Path) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not path.exists():
        raise ConfigError(f"config file not found: {path}", remedy=f"create {path}")
    cfg.read(path)
    return cfg


def load_settings(
    system_ini: Path,
    user_ini: Path,
    *,
    custom_ini: Path | None = None,
    overrides: dict[str, dict[str, str]] | None = None,
) -> Settings:
    merged: dict[str, dict[str, str]] = {}
    _layer(merged, _read(system_ini))
    _layer(merged, _read(user_ini))
    if custom_ini is not None:
        _layer(merged, _read(custom_ini))
    if overrides:
        for section, kv in overrides.items():
            merged.setdefault(section, {}).update(kv)

    built: dict[str, _Base] = {}
    for section, model in _SECTION_MODEL.items():
        try:
            built[section] = model(**merged.get(section, {}))
        except ValidationError as exc:
            raise ConfigError(
                f"invalid [{section}] configuration: {exc.errors()[0]['msg']}",
                remedy=f"check the [{section}] section of your .ini",
            ) from exc
    return Settings(**built)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_config.py -v && uv run mypy src/likedbg`
Expected: 6 passed; mypy clean.

- [ ] **Step 6: Commit**

```bash
git add src/likedbg/config.py tests/test_config.py tests/fixtures/system.ini tests/fixtures/user.ini
git commit -m "feat: typed Pydantic config + INI loader (replaces cfg_setter)"
```

---

### Task 4: `host_profile` — capability detection

Resolve OS/arch/accel/debuggee-mode/storage/addresses once, via **injectable probes** so it
is testable with no real host capabilities. Implements the §4.4 resolution matrix and the
§4.6 storage strategy.

**Files:**
- Create: `src/likedbg/host_profile.py`
- Create: `tests/test_host_profile.py`

**Interfaces:**
- Consumes: `likedbg.config.Settings`, `likedbg.config.Arch`, `likedbg.errors.HostCapabilityError`.
- Produces:
  - `Probes` (frozen dataclass) with callables:
    `system() -> str` ("linux"/"darwin"), `machine() -> str` ("arm64"/"x86_64"),
    `kvm_accessible() -> bool`, `hvf_supported() -> bool`,
    `native_qemu_present(arch: Arch) -> bool`, `workspace_case_sensitive(path: Path) -> bool`.
  - `HostProfile` (frozen dataclass) with fields `os: str`, `host_arch: str`,
    `accel: Literal["kvm","hvf","tcg"]`, `debuggee_mode: Literal["in-container","native-host"]`,
    `storage_mode: Literal["bind","volume"]`, `gdbstub_addr: str`, `ssh_addr: str`.
  - `HostProfile.detect(settings: Settings, workspace: Path, probes: Probes = Probes()) -> HostProfile`
    — raises `HostCapabilityError` when an explicit `accel` override is unsatisfiable.

- [ ] **Step 1: Write the failing test**

Create `tests/test_host_profile.py`:

```python
from pathlib import Path

import pytest

from likedbg.config import Settings
from likedbg.errors import HostCapabilityError
from likedbg.host_profile import HostProfile
from likedbg.host_profile import Probes


def _settings(arch="arm64", accel="auto", mac_storage="auto"):
    return Settings.model_validate(
        {"general": {"arch": arch, "mac_storage": mac_storage}, "debuggee": {"accel": accel}}
    )


def _probes(*, system, machine, kvm=False, hvf=False, qemu=False, case_sensitive=True):
    return Probes(
        system=lambda: system,
        machine=lambda: machine,
        kvm_accessible=lambda: kvm,
        hvf_supported=lambda: hvf,
        native_qemu_present=lambda arch: qemu,
        workspace_case_sensitive=lambda path: case_sensitive,
    )


def test_arm64_on_arm_mac_uses_native_hvf():
    p = _probes(system="darwin", machine="arm64", hvf=True, qemu=True)
    hp = HostProfile.detect(_settings("arm64"), Path("/ws"), p)
    assert (hp.accel, hp.debuggee_mode) == ("hvf", "native-host")
    assert hp.gdbstub_addr == "host.docker.internal"


def test_x86_on_arm_mac_stays_in_container_tcg():
    p = _probes(system="darwin", machine="arm64", hvf=True, qemu=False)
    hp = HostProfile.detect(_settings("x86_64"), Path("/ws"), p)
    assert (hp.accel, hp.debuggee_mode) == ("tcg", "in-container")


def test_linux_same_arch_with_kvm():
    p = _probes(system="linux", machine="x86_64", kvm=True)
    hp = HostProfile.detect(_settings("x86_64"), Path("/ws"), p)
    assert (hp.accel, hp.debuggee_mode) == ("kvm", "in-container")
    assert hp.gdbstub_addr == "localhost"


def test_auto_degrades_to_tcg_when_no_accel():
    p = _probes(system="darwin", machine="arm64", hvf=False, qemu=False)
    hp = HostProfile.detect(_settings("arm64"), Path("/ws"), p)
    assert hp.accel == "tcg"


def test_explicit_unsatisfiable_accel_raises():
    p = _probes(system="linux", machine="x86_64", kvm=False)
    with pytest.raises(HostCapabilityError):
        HostProfile.detect(_settings("x86_64", accel="kvm"), Path("/ws"), p)


def test_storage_volume_on_case_insensitive_mac():
    p = _probes(system="darwin", machine="arm64", hvf=True, qemu=True, case_sensitive=False)
    hp = HostProfile.detect(_settings("arm64"), Path("/ws"), p)
    assert hp.storage_mode == "volume"


def test_storage_bind_on_linux_always():
    p = _probes(system="linux", machine="x86_64", kvm=True, case_sensitive=False)
    hp = HostProfile.detect(_settings("x86_64"), Path("/ws"), p)
    assert hp.storage_mode == "bind"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_host_profile.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.host_profile'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/host_profile.py`:

```python
"""Host-capability detection. All side-effecting checks go through `Probes` so the
resolution logic is pure and unit-testable."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Literal

from likedbg.config import Arch
from likedbg.config import Settings
from likedbg.errors import HostCapabilityError

Accel = Literal["kvm", "hvf", "tcg"]
DebuggeeMode = Literal["in-container", "native-host"]
StorageMode = Literal["bind", "volume"]


def _real_system() -> str:
    return platform.system().lower()


def _real_machine() -> str:
    m = platform.machine().lower()
    return "arm64" if m in {"arm64", "aarch64"} else "x86_64"


def _real_kvm_accessible() -> bool:
    return Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK)


def _real_hvf_supported() -> bool:
    try:
        out = subprocess.run(
            ["sysctl", "-n", "kern.hv_support"], capture_output=True, text=True, check=False
        )
    except OSError:
        return False
    return out.stdout.strip() == "1"


def _real_native_qemu_present(arch: Arch) -> bool:
    binary = "qemu-system-aarch64" if arch == "arm64" else "qemu-system-x86_64"
    return shutil.which(binary) is not None


def _real_case_sensitive(path: Path) -> bool:
    base = path if path.exists() else path.parent
    if not base.exists():
        base = Path(tempfile.gettempdir())
    probe = base / ".likedbg_CaseProbe"
    lower = base / ".likedbg_caseprobe"
    try:
        probe.write_text("x")
        return not lower.exists()
    except OSError:
        return True
    finally:
        probe.unlink(missing_ok=True)


@dataclass(frozen=True)
class Probes:
    system: Callable[[], str] = _real_system
    machine: Callable[[], str] = _real_machine
    kvm_accessible: Callable[[], bool] = _real_kvm_accessible
    hvf_supported: Callable[[], bool] = _real_hvf_supported
    native_qemu_present: Callable[[Arch], bool] = _real_native_qemu_present
    workspace_case_sensitive: Callable[[Path], bool] = _real_case_sensitive


@dataclass(frozen=True)
class HostProfile:
    os: str
    host_arch: str
    accel: Accel
    debuggee_mode: DebuggeeMode
    storage_mode: StorageMode
    gdbstub_addr: str
    ssh_addr: str

    @classmethod
    def detect(cls, settings: Settings, workspace: Path, probes: Probes = Probes()) -> HostProfile:
        os_name = probes.system()
        host_arch = probes.machine()
        guest_arch = settings.general.arch
        same_arch = guest_arch == host_arch

        capable_native_hvf = os_name == "darwin" and same_arch and probes.hvf_supported() and probes.native_qemu_present(guest_arch)
        capable_kvm = os_name == "linux" and same_arch and probes.kvm_accessible()

        requested = settings.debuggee.accel
        accel, mode = cls._resolve_accel(requested, capable_native_hvf, capable_kvm, os_name)

        storage = cls._resolve_storage(settings, os_name, workspace, probes)
        addr = "host.docker.internal" if mode == "native-host" else "localhost"
        return cls(
            os=os_name,
            host_arch=host_arch,
            accel=accel,
            debuggee_mode=mode,
            storage_mode=storage,
            gdbstub_addr=addr,
            ssh_addr=addr,
        )

    @staticmethod
    def _resolve_accel(requested: str, native_hvf: bool, kvm: bool, os_name: str) -> tuple[Accel, DebuggeeMode]:
        if requested == "auto":
            if native_hvf:
                return "hvf", "native-host"
            if kvm:
                return "kvm", "in-container"
            return "tcg", "in-container"
        if requested == "hvf":
            if not native_hvf:
                raise HostCapabilityError(
                    "accel=hvf requested but HVF/native QEMU unavailable for this target",
                    remedy="use accel=auto, or run on an arm64 macOS host with qemu installed",
                )
            return "hvf", "native-host"
        if requested == "kvm":
            if not kvm:
                raise HostCapabilityError(
                    "accel=kvm requested but /dev/kvm is not accessible",
                    remedy="add your user to the 'kvm' group, or use accel=auto",
                )
            return "kvm", "in-container"
        return "tcg", "in-container"

    @staticmethod
    def _resolve_storage(settings: Settings, os_name: str, workspace: Path, probes: Probes) -> StorageMode:
        if os_name != "darwin":
            return "bind"
        override = settings.general.mac_storage
        if override == "bind":
            return "bind"
        if override == "volume":
            return "volume"
        return "bind" if probes.workspace_case_sensitive(workspace) else "volume"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_host_profile.py -v && uv run mypy src/likedbg`
Expected: 7 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/host_profile.py tests/test_host_profile.py
git commit -m "feat: HostProfile capability detection with injectable probes"
```

---

### Task 5: `container_service` — runtime-agnostic Docker wrapper

Wrap docker-py so stages get build/run/exec/stop without inheriting a god base-class.
Injectable client → testable with a mock.

**Files:**
- Create: `src/likedbg/container_service.py`
- Create: `tests/test_container_service.py`

**Interfaces:**
- Consumes: `likedbg.errors.ContainerError`.
- Produces:
  - `ExecResult` (frozen dataclass): `.exit_code: int`, `.output: str`.
  - `ContainerService(client: object, *, docker_mnt: str = "/io")` with:
    - `image_exists(tag: str) -> bool`
    - `build_image(dockerfile: str, tag: str, buildargs: dict[str, str], *, nocache: bool = False) -> None`
      (raises `ContainerError` on `docker.errors.APIError`)
    - `run_detached(image: str, **kwargs: object) -> object` (returns the container handle)
    - `exec(container: object, cmd: str, *, workdir: str | None = None) -> ExecResult`
      (raises `ContainerError` on non-zero exit)
    - `stop(container: object) -> None`

- [ ] **Step 1: Write the failing test**

Create `tests/test_container_service.py`:

```python
from types import SimpleNamespace

import docker.errors
import pytest

from likedbg.container_service import ContainerService
from likedbg.errors import ContainerError


class FakeImages:
    def __init__(self, existing):
        self._existing = existing

    def get(self, tag):
        if tag in self._existing:
            return SimpleNamespace(tags=[tag])
        raise docker.errors.ImageNotFound(tag)


class FakeContainers:
    def __init__(self):
        self.run_kwargs = None

    def run(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return SimpleNamespace(id="c123")


class FakeClient:
    def __init__(self, existing=()):
        self.images = FakeImages(set(existing))
        self.containers = FakeContainers()


def test_image_exists_true_false():
    svc = ContainerService(FakeClient(existing=["like_kbuilder_arm64"]))
    assert svc.image_exists("like_kbuilder_arm64") is True
    assert svc.image_exists("nope") is False


def test_run_detached_passes_through():
    client = FakeClient()
    svc = ContainerService(client)
    handle = svc.run_detached("img", detach=True, tty=True)
    assert handle.id == "c123"
    assert client.containers.run_kwargs["image"] == "img"


def test_exec_returns_result_on_success():
    container = SimpleNamespace(
        exec_run=lambda cmd, workdir=None: SimpleNamespace(exit_code=0, output=b"ok\n")
    )
    svc = ContainerService(FakeClient())
    res = svc.exec(container, "true")
    assert res.exit_code == 0
    assert res.output == "ok\n"


def test_exec_raises_on_nonzero():
    container = SimpleNamespace(
        exec_run=lambda cmd, workdir=None: SimpleNamespace(exit_code=2, output=b"boom")
    )
    svc = ContainerService(FakeClient())
    with pytest.raises(ContainerError):
        svc.exec(container, "false")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_container_service.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.container_service'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/container_service.py`:

```python
"""Thin, runtime-agnostic wrapper over docker-py used by the pipeline stages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import docker.errors

from likedbg.errors import ContainerError


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    output: str


class ContainerService:
    def __init__(self, client: Any, *, docker_mnt: str = "/io") -> None:
        self._client = client
        self.docker_mnt = docker_mnt

    def image_exists(self, tag: str) -> bool:
        try:
            self._client.images.get(tag)
        except docker.errors.ImageNotFound:
            return False
        return True

    def build_image(
        self, dockerfile: str, tag: str, buildargs: dict[str, str], *, nocache: bool = False
    ) -> None:
        try:
            self._client.images.build(
                path=".", dockerfile=dockerfile, tag=tag, buildargs=buildargs, nocache=nocache, rm=True
            )
        except docker.errors.APIError as exc:
            raise ContainerError(
                f"failed to build image {tag} from {dockerfile}: {exc}",
                remedy="check the Dockerfile and that the container runtime is running",
            ) from exc

    def run_detached(self, image: str, **kwargs: Any) -> Any:
        return self._client.containers.run(image, **kwargs)

    def exec(self, container: Any, cmd: str, *, workdir: str | None = None) -> ExecResult:
        result = container.exec_run(cmd, workdir=workdir)
        output = result.output.decode() if isinstance(result.output, bytes) else str(result.output)
        if result.exit_code != 0:
            raise ContainerError(
                f"command failed (exit {result.exit_code}): {cmd}\n{output}",
                remedy="inspect the command output above",
            )
        return ExecResult(exit_code=result.exit_code, output=output)

    def stop(self, container: Any) -> None:
        container.stop()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_container_service.py -v && uv run mypy src/likedbg`
Expected: 4 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/container_service.py tests/test_container_service.py
git commit -m "feat: ContainerService wrapping docker-py (build/run/exec/stop)"
```

---

### Task 6: `session` — tmux abstraction

Move all tmux interaction behind one object with an injectable command runner.

**Files:**
- Create: `src/likedbg/session.py`
- Create: `tests/test_session.py`

**Interfaces:**
- Consumes: `likedbg.errors.SessionError`.
- Produces:
  - `Session(name: str, runner: Callable[[list[str]], int] = ...)` with:
    - `select_pane(index: int) -> None`
    - `split(direction: Literal["h", "v"], percent: int) -> None`
    - `send_keys(command: str) -> None`
    - `kill() -> None`
  - Each method shells `tmux <args>` via the runner; the runner returns an exit code and a
    non-zero code raises `SessionError`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_session.py`:

```python
import pytest

from likedbg.errors import SessionError
from likedbg.session import Session


class Recorder:
    def __init__(self, rc=0):
        self.calls: list[list[str]] = []
        self.rc = rc

    def __call__(self, args: list[str]) -> int:
        self.calls.append(args)
        return self.rc


def test_select_pane_issues_tmux_selectp():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).select_pane(2)
    assert rec.calls == [["tmux", "selectp", "-t", "2"]]


def test_split_horizontal_with_percent():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).split("h", 50)
    assert rec.calls == [["tmux", "splitw", "-h", "-p", "50"]]


def test_send_keys_appends_enter():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).send_keys("echo hi")
    assert rec.calls == [["tmux", "send-keys", "echo hi", "C-m"]]


def test_nonzero_runner_raises_sessionerror():
    rec = Recorder(rc=1)
    with pytest.raises(SessionError):
        Session("LIKE-DBG", runner=rec).select_pane(0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_session.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.session'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/session.py`:

```python
"""tmux session/pane orchestration behind a single, testable object."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Literal

from likedbg.errors import SessionError


def _real_runner(args: list[str]) -> int:
    return subprocess.run(args, check=False).returncode


class Session:
    def __init__(self, name: str, runner: Callable[[list[str]], int] = _real_runner) -> None:
        self.name = name
        self._runner = runner

    def _tmux(self, *args: str) -> None:
        rc = self._runner(["tmux", *args])
        if rc != 0:
            raise SessionError(
                f"tmux command failed (exit {rc}): {' '.join(args)}",
                remedy="ensure you are running inside a tmux session",
            )

    def select_pane(self, index: int) -> None:
        self._tmux("selectp", "-t", str(index))

    def split(self, direction: Literal["h", "v"], percent: int) -> None:
        self._tmux("splitw", f"-{direction}", "-p", str(percent))

    def send_keys(self, command: str) -> None:
        self._tmux("send-keys", command, "C-m")

    def kill(self) -> None:
        self._tmux("kill-pane", "-a", "-t", "0")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_session.py -v && uv run mypy src/likedbg`
Expected: 4 passed; mypy clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/session.py tests/test_session.py
git commit -m "feat: tmux Session abstraction with injectable runner"
```

---

### Task 7: `pipeline` — context, stage protocol, runner

The seam that threads typed state through stages and replaces the `stage1..stage6` nesting.

**Files:**
- Create: `src/likedbg/pipeline.py`
- Create: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `likedbg.config.Settings`, `likedbg.host_profile.HostProfile`.
- Produces:
  - `PipelineContext` (mutable dataclass): `.settings: Settings`, `.host: HostProfile`,
    `.kernel_archive: Path | None = None`, `.kernel_root: Path | None = None`,
    `.kernel_status: str | None = None`, `.rootfs_image: Path | None = None`.
  - `Stage` (runtime-checkable Protocol): attribute `name: str`; methods
    `run(ctx: PipelineContext) -> PipelineContext` and `should_skip(ctx: PipelineContext) -> bool`.
  - `Pipeline(stages: list[Stage])` with `run(ctx: PipelineContext) -> PipelineContext` that
    skips stages whose `should_skip` is true and runs the rest in order.

- [ ] **Step 1: Write the failing test**

Create `tests/test_pipeline.py`:

```python
from pathlib import Path

from likedbg.config import Settings
from likedbg.host_profile import HostProfile
from likedbg.pipeline import Pipeline
from likedbg.pipeline import PipelineContext


def _ctx():
    host = HostProfile(
        os="linux", host_arch="x86_64", accel="tcg", debuggee_mode="in-container",
        storage_mode="bind", gdbstub_addr="localhost", ssh_addr="localhost",
    )
    return PipelineContext(settings=Settings(), host=host)


class RecordStage:
    def __init__(self, name, skip=False):
        self.name = name
        self._skip = skip
        self.ran = False

    def should_skip(self, ctx):
        return self._skip

    def run(self, ctx):
        self.ran = True
        ctx.kernel_status = self.name
        return ctx


def test_runs_stages_in_order():
    a, b = RecordStage("a"), RecordStage("b")
    Pipeline([a, b]).run(_ctx())
    assert a.ran and b.ran


def test_skips_when_should_skip_true():
    a = RecordStage("a", skip=True)
    Pipeline([a]).run(_ctx())
    assert a.ran is False


def test_context_threads_through():
    ctx = _ctx()
    out = Pipeline([RecordStage("download"), RecordStage("build")]).run(ctx)
    assert out.kernel_status == "build"  # last stage wrote it
    assert out is ctx
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_pipeline.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.pipeline'`.

- [ ] **Step 3: Write the implementation**

Create `src/likedbg/pipeline.py`:

```python
"""Pipeline context + stage protocol + runner. The insertion seam for all stages."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from typing import runtime_checkable

from loguru import logger

from likedbg.config import Settings
from likedbg.host_profile import HostProfile


@dataclass
class PipelineContext:
    settings: Settings
    host: HostProfile
    kernel_archive: Path | None = None
    kernel_root: Path | None = None
    kernel_status: str | None = None
    rootfs_image: Path | None = None


@runtime_checkable
class Stage(Protocol):
    name: str

    def run(self, ctx: PipelineContext) -> PipelineContext: ...

    def should_skip(self, ctx: PipelineContext) -> bool: ...


class Pipeline:
    def __init__(self, stages: list[Stage]) -> None:
        self._stages = stages

    def run(self, ctx: PipelineContext) -> PipelineContext:
        for stage in self._stages:
            if stage.should_skip(ctx):
                logger.debug(f"skipping stage: {stage.name}")
                continue
            logger.info(f"running stage: {stage.name}")
            ctx = stage.run(ctx)
        return ctx
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_pipeline.py -v && uv run mypy src/likedbg`
Expected: 3 passed; mypy clean.

- [ ] **Step 5: Full green check + commit**

```bash
uv run pytest -v
uv run ruff format --check .
uv run ruff check .
uv run mypy src/likedbg
git add src/likedbg/pipeline.py tests/test_pipeline.py
git commit -m "feat: PipelineContext + Stage protocol + Pipeline runner"
```

- [ ] **Step 6: Merge the feature branch into `dev`**

```bash
git checkout dev
git merge --no-ff feat/m1-foundation -m "merge: M1 foundation scaffold (typed core + tooling)"
```

---

## What this plan deliberately defers (next M1 plans)

This plan is the deterministic, fully-mockable base. The following are written **after** this
lands, grounded in observed behavior:

- **Plan 2 — Build chain & arm64 plumbing PoC:** modern base image + kbuilder Dockerfile
  (clang universal cross), bootstrap (colima + qemu + binfmt + uv), the `Download`/`Unpack`/
  `Build` stages on top of `ContainerService`, the storage-strategy (bind/volume) wiring, and
  the **early-boot `start_kernel` breakpoint PoC** on arm64/HVF.
- **Plan 3 — Rootfs + native QEMU + debugger → full arm64 session:** `Rootfs` stage,
  `NativeQemu`/`InContainerQemu` debuggee backends + typed argv builder, `Debugger` stage
  (TCP gdbstub attach over `host.docker.internal`), tmux wiring via `Session`, reaching the
  **M1 exit gate** (boot-to-shell + interactive breakpoints).

## Self-Review

- **Spec coverage (foundation slice):** typed Pydantic config replacing `cfg_setter` (Task 3 ✓);
  `errors` hierarchy with remedies (Task 2 ✓); `HostProfile` accel/storage resolution per §4.4/§4.6
  (Task 4 ✓); `ContainerService` composition-over-inheritance + `docker exec` (Task 5 ✓);
  `Session` tmux module (Task 6 ✓); `PipelineContext`/`Stage`/`Pipeline` (Task 7 ✓); tooling
  uv+ruff+mypy+pre-commit, Python 3.12, drop black/poetry/fabric (Task 1 ✓). Stage
  implementations, Dockerfiles, bootstrap, QEMU backends, and the actual arm64 build/boot are
  explicitly deferred to Plans 2–3 above.
- **Placeholder scan:** none — every step contains runnable code/commands.
- **Type consistency:** `Settings`/`HostProfile`/`PipelineContext`/`ContainerService`/`Session`
  names and signatures match across Produces/Consumes blocks and test usages; `Arch`/`Accel`/
  `StorageMode` literals are consistent.

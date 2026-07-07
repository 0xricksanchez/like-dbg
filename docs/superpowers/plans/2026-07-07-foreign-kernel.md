# Foreign Kernel / CTF Adopt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let like-dbg boot + debug a kernel it did not build (a CTF `bzImage`/`Image` + `vmlinux` + `initramfs.cpio`) via `start_kgdb -c <challenge>`, attach gdb with symbols, drive the busybox console, and deliver an exploit into the foreign initramfs by repack or live console-upload.

**Architecture:** A new `[foreign]` TOML section (presence of `[foreign].image` selects the path) drives a Manifest-free pipeline `ForeignAdoptStage → [ForeignRepackStage] → DebuggeeStage → DebuggerStage`, mirroring `cmd_use`/`build_use_pipeline`. Arch is auto-detected from the `vmlinux` ELF and injected as a `cli_overrides={"general":{"arch":…}}` before host-profile detection. A new standalone `like_musl` container image carries `cpio` + decompressors + cross-musl toolchains for both arches; it extracts vmlinux (x86), repacks the initramfs, and cross-compiles the exploit to the foreign arch. `build_qemu_argv` gains a foreign branch that uses the challenge cmdline verbatim (no imposed mitigations).

**Tech Stack:** Python 3.12, pydantic v2, docker-py (via `ContainerService`), tmux (via `Session`), QEMU, pytest. Dev loop: `just test` = `uv run pytest -q`; `just lint` = `uv run ruff check . && uv run ruff format --check . && uv run mypy src/likedbg`.

## Global Constraints

- **Python 3.12**, `ruff` line-length 120, `ruff format`, `mypy --strict` over `src/likedbg` only (tests are not type-checked). `force-single-line` isort: one import per line.
- **Config models** subclass `config._Base` (pydantic v2, `frozen=True`, `extra="forbid"`). Tuple fields arrive as TOML `list`; validators use `mode="before"`, iterate the raw list, and return `v` unchanged.
- **Errors** subclass `errors.LikeDbgError`; constructor is `LikeDbgError(message, *, remedy=None)`. A `ForeignError(LikeDbgError)` lives feature-locally in `src/likedbg/foreign.py` (mirroring `ExploitError` in `exploit.py`).
- **Container idiom:** `c = container.run_detached(image, volumes={host: {"bind": dst, "mode": "ro"|"rw"}}, detach=True, tty=True)` → `container.exec(c, cmd)` (raises `ContainerError` on nonzero exit) → `finally: container.stop(c)`. `container` is a `ContainerService`.
- **Foreign path fields accept absolute OR workspace-relative** (a deliberate exception to `_reject_unsafe_path`), rejecting only `..` traversal.
- **Authoritative cmdline:** the foreign branch imposes NO mitigation flags; it adds only `console=<ttyS0|ttyAMA0>` (if absent) + gdbstub, then layers `extra_boot_args`; `qemu_extra` appends to the QEMU argv.
- **Exploit is never auto-run.** Delivery is repack (reliable) or console-upload (optional live); the user runs `/exploit` manually.
- **Arch strings** are `"x86_64"` / `"arm64"` (QEMU/`target_arch`), but the arm64 cross toolchain is spelled `aarch64-linux-musl-gcc`.
- Commands run from the repo root `/Users/krah/Git/private/like-dbg`. Work on branch `feat/foreign-kernel` (off `dev`); merge locally when done.

---

## File Structure

**New files:**
- `src/likedbg/foreign.py` — `ForeignError`, `ForeignKernel`, `detect_arch`, `resolve_input_path`, `extract_vmlinux`, `resolve_foreign`, `repack_initramfs`, `console_upload`.
- `src/likedbg/stages/foreign.py` — `ForeignAdoptStage`, `ForeignRepackStage`.
- `.dockerfile_musl` — the `like_musl` image (root user; cpio + decompressors + cross-musl).
- `io/scripts/extract-vmlinux.sh` — the vmlinux carve script, COPY'd into `like_musl`.
- `tests/test_foreign.py`, `tests/test_stage_foreign.py`, `tests/test_cli_foreign.py`.

**Modified files:**
- `src/likedbg/config.py` — `_reject_traversal`, `ForeignCfg`, `Settings.foreign`, `_SECTION_MODELS`.
- `src/likedbg/constants.py` — `MUSL_IMAGE`.
- `src/likedbg/images.py` — musl `ImageSpec`, `required_for_foreign`, `foreign_prep_images`.
- `src/likedbg/qemu.py` — `build_qemu_argv` foreign branch (`foreign_cmdline`, `qemu_extra`).
- `src/likedbg/pipeline.py` — `PipelineContext.foreign_cmdline`, `PipelineContext.qemu_extra`.
- `src/likedbg/stages/debuggee.py` — thread `foreign_cmdline`/`qemu_extra` into `build_qemu_argv`.
- `src/likedbg/session.py` — `send_keys`.
- `src/likedbg/cli.py` — `cmd_foreign`, `build_foreign_pipeline`, `cmd_upload`, `--upload` flag, dispatch.
- `tests/test_images.py` — extend the exact-tag-set assertion.
- `tests/test_session.py` — update the `send_keys`-absence assertion.
- `docs/adr/ADR-0010-*.md`, `docs/CONTEXT.md`, `configs/scenarios/` example.

---

### Task 1: `ForeignCfg` config section + traversal-only validator

**Files:**
- Modify: `src/likedbg/config.py`
- Test: `tests/test_config_models.py`, `tests/test_config_loader.py`

**Interfaces:**
- Consumes: `config._Base`, `config._reject_unsafe_path`, `config.ConfigError`, `pydantic.field_validator`.
- Produces: `config._reject_traversal(p: str) -> None`; `config.ForeignCfg(_Base)` with fields `image: str=""`, `vmlinux: str=""`, `initramfs: str=""`, `cmdline: str=""`, `arch: str=""`, `qemu_extra: tuple[str, ...]=()`, `exploit: str=""`; `Settings.foreign: ForeignCfg`; `_SECTION_MODELS["foreign"] = ForeignCfg`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_config_models.py`:

```python
from likedbg.config import ForeignCfg


def test_foreign_cfg_defaults_empty_and_presence_selects() -> None:
    f = ForeignCfg()
    assert f.image == "" and f.vmlinux == "" and f.initramfs == ""
    assert f.cmdline == "" and f.arch == "" and f.exploit == ""
    assert f.qemu_extra == ()
    # presence of image is the selector the CLI keys on
    assert ForeignCfg(image="ctf/lk01/bzImage").image == "ctf/lk01/bzImage"


def test_foreign_cfg_accepts_absolute_paths() -> None:
    """Foreign inputs are read-only external artifacts: absolute paths ARE allowed."""
    f = ForeignCfg(
        image="/home/ctf/lk01/bzImage",
        vmlinux="/home/ctf/lk01/vmlinux",
        initramfs="/home/ctf/lk01/initramfs.cpio.gz",
        exploit="/home/ctf/lk01/exploit.c",
    )
    assert f.image == "/home/ctf/lk01/bzImage"
    assert f.vmlinux == "/home/ctf/lk01/vmlinux"


def test_foreign_cfg_rejects_dotdot_traversal() -> None:
    with pytest.raises(ConfigError, match=r"\.\.|traversal"):
        ForeignCfg(image="../../etc/passwd")


def test_foreign_cfg_qemu_extra_is_tuple() -> None:
    f = ForeignCfg(qemu_extra=["-cpu", "qemu64,+smep"])
    assert f.qemu_extra == ("-cpu", "qemu64,+smep")


def test_foreign_cfg_rejects_unknown_key() -> None:
    with pytest.raises(ValidationError):
        ForeignCfg(bogus=1)  # type: ignore[call-arg]
```

Add to `tests/test_config_loader.py`:

```python
def test_foreign_section_loads_through_scenario(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[general]\narch = "native"\n')
    _write(
        tmp_path / "configs" / "scenarios" / "lk01.toml",
        '[foreign]\nimage = "ctf/lk01/bzImage"\ncmdline = "quiet"\n',
    )
    cr = load_config(tmp_path, scenario=tmp_path / "configs" / "scenarios" / "lk01.toml")
    assert cr.settings.foreign.image == "ctf/lk01/bzImage"
    assert cr.settings.foreign.cmdline == "quiet"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config_models.py -k foreign tests/test_config_loader.py -k foreign -v`
Expected: FAIL with `ImportError: cannot import name 'ForeignCfg'`.

- [ ] **Step 3: Implement**

In `src/likedbg/config.py`, add after `_reject_unsafe_path` (near line 36):

```python
def _reject_traversal(p: str) -> None:
    """Raise ConfigError only on '..' traversal; absolute paths are allowed.

    Foreign inputs are read-only external artifacts a CTF challenge ships anywhere
    (e.g. ~/ctf/<name>/), so absolute paths are permitted here — unlike _reject_unsafe_path.
    """
    if ".." in Path(p).parts:
        raise ConfigError(
            f"unsafe path {p!r}: '..' traversal is not allowed",
            remedy="use a forward-only path (absolute or workspace-relative)",
        )
```

Add the model near `BuildCfg` (after it, ~line 94):

```python
class ForeignCfg(_Base):
    # Presence of `image` selects the foreign (CTF-adopt) path. Path fields accept absolute
    # OR workspace-relative (external read-only artifacts); only '..' traversal is rejected.
    image: str = ""
    vmlinux: str = ""
    initramfs: str = ""
    cmdline: str = ""
    arch: str = ""  # optional override; else auto-detected from the vmlinux ELF
    qemu_extra: tuple[str, ...] = ()
    exploit: str = ""

    @field_validator("image", "vmlinux", "initramfs", "exploit", mode="before")
    @classmethod
    def _validate_foreign_path(cls, v: object) -> object:
        if v:
            _reject_traversal(str(v))
        return v
```

Register the section — in `Settings` (after `debugging`, ~line 138) add `foreign: ForeignCfg = ForeignCfg()`, and in `_SECTION_MODELS` (~line 160) add `"foreign": ForeignCfg,`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_config_models.py tests/test_config_loader.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/config.py && uv run mypy src/likedbg
git add src/likedbg/config.py tests/test_config_models.py tests/test_config_loader.py
git commit -m "feat(foreign): add [foreign] config section + traversal-only path validator"
```

---

### Task 2: `ForeignError` + `ForeignKernel` + `detect_arch`

**Files:**
- Create: `src/likedbg/foreign.py`
- Test: `tests/test_foreign.py`

**Interfaces:**
- Consumes: `errors.LikeDbgError`.
- Produces: `foreign.ForeignError(LikeDbgError)`; `foreign.ForeignKernel` (frozen dataclass: `image: Path`, `vmlinux: Path`, `initramfs: Path | None`, `arch: str`, `cmdline: str`); `foreign.detect_arch(vmlinux: Path) -> str` returning `"x86_64"` or `"arm64"`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_foreign.py`:

```python
from pathlib import Path

import pytest

from likedbg.errors import LikeDbgError
from likedbg.foreign import ForeignError
from likedbg.foreign import ForeignKernel
from likedbg.foreign import detect_arch


def _elf_header(e_machine: bytes) -> bytes:
    # e_ident(16) = magic(4) + class(1)=64bit + data(1)=LE + version(1) + osabi/pad(9);
    # e_type(2) at 16; e_machine(2) at 18 (little-endian).
    e_ident = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 8
    return e_ident + b"\x02\x00" + e_machine + b"\x00" * 20


def test_detect_arch_x86_64(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\x3e\x00"))  # EM_X86_64 = 62
    assert detect_arch(v) == "x86_64"


def test_detect_arch_aarch64(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\xb7\x00"))  # EM_AARCH64 = 183
    assert detect_arch(v) == "arm64"


def test_detect_arch_non_elf_raises(tmp_path: Path) -> None:
    v = tmp_path / "notelf"
    v.write_bytes(b"MZ\x90\x00not an elf")
    with pytest.raises(ForeignError, match="not an ELF"):
        detect_arch(v)


def test_detect_arch_unknown_machine_raises(tmp_path: Path) -> None:
    v = tmp_path / "vmlinux"
    v.write_bytes(_elf_header(b"\x28\x00"))  # EM_ARM (32-bit) = 40, unsupported
    with pytest.raises(ForeignError, match="e_machine"):
        detect_arch(v)


def test_foreign_error_is_likedbg_error() -> None:
    assert issubclass(ForeignError, LikeDbgError)


def test_foreign_kernel_is_frozen(tmp_path: Path) -> None:
    fk = ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=tmp_path / "initramfs.cpio.gz",
        arch="x86_64",
        cmdline="quiet",
    )
    with pytest.raises(Exception):
        fk.arch = "arm64"  # type: ignore[misc]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_foreign.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'likedbg.foreign'`.

- [ ] **Step 3: Implement**

Create `src/likedbg/foreign.py`:

```python
"""Foreign-kernel (CTF adopt) host-side logic: arch detection, vmlinux extraction,
initramfs repack, and live console upload. See ADR-0010."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from likedbg.errors import LikeDbgError

_EM_TO_ARCH = {62: "x86_64", 183: "arm64"}  # EM_X86_64, EM_AARCH64


class ForeignError(LikeDbgError):
    """A foreign-kernel adopt/boot/exploit-delivery operation could not be set up."""


@dataclass(frozen=True)
class ForeignKernel:
    image: Path
    vmlinux: Path
    initramfs: Path | None
    arch: str
    cmdline: str


def detect_arch(vmlinux: Path) -> str:
    """Return 'x86_64'/'arm64' from the ELF e_machine, else raise ForeignError."""
    head = vmlinux.read_bytes()[:20]
    if head[:4] != b"\x7fELF":
        raise ForeignError(
            f"{vmlinux} is not an ELF file (cannot detect arch)",
            remedy="provide a real [foreign].vmlinux, or set [foreign].arch",
        )
    endian = "little" if head[5] == 1 else "big"
    e_machine = int.from_bytes(head[18:20], endian)  # type: ignore[arg-type]
    arch = _EM_TO_ARCH.get(e_machine)
    if arch is None:
        raise ForeignError(
            f"unsupported ELF e_machine {e_machine} in {vmlinux}",
            remedy="set [foreign].arch to x86_64 or arm64",
        )
    return arch
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_foreign.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/foreign.py && uv run mypy src/likedbg
git add src/likedbg/foreign.py tests/test_foreign.py
git commit -m "feat(foreign): ForeignError + ForeignKernel + detect_arch (ELF e_machine)"
```

---

### Task 3: `like_musl` image (constants + ImageSpec + dockerfile + extract script + selectors)

**Files:**
- Modify: `src/likedbg/constants.py`, `src/likedbg/images.py`, `tests/test_images.py`
- Create: `.dockerfile_musl`, `io/scripts/extract-vmlinux.sh`
- Test: `tests/test_images.py`

**Interfaces:**
- Consumes: `images.ImageSpec`, `images.IMAGES`, `constants.BASE_IMAGE`.
- Produces: `constants.MUSL_IMAGE = "like_musl:latest"`; a `MUSL_IMAGE` `ImageSpec` in `IMAGES`; `images.required_for_foreign(host) -> tuple[ImageSpec, ...]`; `images.foreign_prep_images() -> tuple[ImageSpec, ...]` (base + musl, needed before host detection).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_images.py`:

```python
from likedbg.constants import BASE_IMAGE
from likedbg.constants import MUSL_IMAGE
from likedbg import images


def test_musl_image_registered() -> None:
    tags = [s.tag for s in images.IMAGES]
    assert MUSL_IMAGE in tags
    musl = next(s for s in images.IMAGES if s.tag == MUSL_IMAGE)
    assert musl.dockerfile == ".dockerfile_musl"
    assert "io/scripts/extract-vmlinux.sh" in musl.build_inputs


def test_foreign_prep_images_are_base_and_musl() -> None:
    tags = {s.tag for s in images.foreign_prep_images()}
    assert tags == {BASE_IMAGE, MUSL_IMAGE}


def test_required_for_foreign_native_host_excludes_debuggee() -> None:
    from likedbg.constants import DEBUGGEE_IMAGE

    class _H:
        debuggee_mode = "native-host"

    tags = {s.tag for s in images.required_for_foreign(_H())}
    assert MUSL_IMAGE in tags and DEBUGGEE_IMAGE not in tags


def test_required_for_foreign_in_container_includes_debuggee() -> None:
    from likedbg.constants import DEBUGGEE_IMAGE

    class _H:
        debuggee_mode = "in-container"

    tags = {s.tag for s in images.required_for_foreign(_H())}
    assert MUSL_IMAGE in tags and DEBUGGEE_IMAGE in tags
```

Update the existing exact-set assertion in `tests/test_images.py::test_images_manifest_shape` (find the set literal `{BASE_IMAGE, KBUILDER_IMAGE, ROOTFS_IMAGE, DEBUGGER_IMAGE, DEBUGGEE_IMAGE}`) to include `MUSL_IMAGE`.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_images.py -q`
Expected: FAIL (`ImportError: MUSL_IMAGE`, and the manifest-shape set mismatch).

- [ ] **Step 3: Implement**

In `src/likedbg/constants.py`, after `DEBUGGEE_IMAGE` (~line 19):

```python
# Standalone musl image: cpio + decompressors + cross-musl toolchains for BOTH arches.
# Runs as root (cpio -idm needs device nodes). Repacks the foreign initramfs, cross-compiles
# the exploit to the foreign arch, and carves vmlinux from a bzImage.
MUSL_IMAGE = "like_musl:latest"
```

In `src/likedbg/images.py`, import the constant (one per line) and add the spec to `IMAGES` right after the `BASE_IMAGE` entry (it is `FROM like_dbg_base`, so it must build after base):

```python
    ImageSpec(
        MUSL_IMAGE,
        ".dockerfile_musl",
        (".dockerfile_musl", "io/scripts/extract-vmlinux.sh"),
        {"USER": "user"},
    ),
```

Add the selectors near `required_for_use` (~line 135):

```python
def foreign_prep_images() -> tuple[ImageSpec, ...]:
    """base + musl — needed before host/arch detection (extract vmlinux, repack)."""
    return tuple(s for s in IMAGES if s.tag in (BASE_IMAGE, MUSL_IMAGE))


def required_for_foreign(host: HostProfile) -> tuple[ImageSpec, ...]:
    """Images a foreign (CTF-adopt) run needs; debuggee only for in-container QEMU."""
    tags = {BASE_IMAGE, MUSL_IMAGE, DEBUGGER_IMAGE}
    if host.debuggee_mode == "in-container":
        tags.add(DEBUGGEE_IMAGE)
    return tuple(s for s in IMAGES if s.tag in tags)
```

Create `io/scripts/extract-vmlinux.sh` (adapted from `ctf/misc/extract-vmlinux.sh`; the args are `<kernel-image> <output-file>`):

```sh
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# extract-vmlinux - carve an uncompressed vmlinux ELF out of a kernel image.
set -eu

check_vmlinux() {
  readelf -h "$1" >/dev/null 2>&1 || return 1
  cat "$1" >"$2"
  exit 0
}

try_decompress() {
  for pos in $(tr "$1\n$2" "\n$2=" <"$img" | grep -abo "^$2"); do
    pos=${pos%%:*}
    tail -c+"$pos" "$img" | $3 >"$tmp" 2>/dev/null || true
    check_vmlinux "$tmp" "$out"
  done
}

img=$1
out=$2
tmp=$(mktemp /tmp/vmlinux-XXXXXX)
trap 'rm -f "$tmp"' EXIT

try_decompress '\037\213\010' xy gunzip
try_decompress '\3757zXZ\000' abcde unxz
try_decompress 'BZh' xy bunzip2
try_decompress '\135\0\0\0' xxx unlzma
try_decompress '\211\114\132' xy 'lzop -d'
try_decompress '\002!L\030' xxx 'lz4 -d'
try_decompress '(\265/\375' xxx unzstd
check_vmlinux "$img" "$out"

echo "extract-vmlinux: cannot find vmlinux in $img" >&2
exit 1
```

Create `.dockerfile_musl` at repo root:

```dockerfile
FROM like_dbg_base:latest
LABEL maintainer="Christopher Krah <mail@0x434b.dev>"
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# cpio + decompressors for unpack/repack + vmlinux carving. binutils gives readelf.
RUN apt-get update && apt-get install -yq --no-install-recommends \
        cpio gzip xz-utils zstd lz4 lzop bzip2 binutils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Cross-musl toolchains for BOTH arches, so the exploit compiles to the FOREIGN arch
# with no qemu emulation. Debian's musl-tools is native-only, so we pull prebuilt
# cross toolchains. musl.cc is a third-party host (occasional downtime = a build-repro
# risk, see plan §Risks); musl-cross-make is the reproducible fallback.
RUN for a in x86_64 aarch64; do \
        curl -fsSL "https://musl.cc/${a}-linux-musl-cross.tgz" -o "/tmp/${a}.tgz" && \
        tar -xzf "/tmp/${a}.tgz" -C /opt && rm "/tmp/${a}.tgz"; \
    done
ENV PATH="/opt/x86_64-linux-musl-cross/bin:/opt/aarch64-linux-musl-cross/bin:${PATH}"

COPY io/scripts/extract-vmlinux.sh /opt/extract-vmlinux.sh
RUN chmod +x /opt/extract-vmlinux.sh

# NOTE: no `USER user` — cpio -idm needs root to create device nodes.
WORKDIR /io
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_images.py -q`
Expected: PASS. (This tests the registry only — the Docker build itself is exercised in the live gate, Task 15.)

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg && uv run mypy src/likedbg
git add src/likedbg/constants.py src/likedbg/images.py .dockerfile_musl io/scripts/extract-vmlinux.sh tests/test_images.py
git commit -m "feat(foreign): register like_musl image (cpio + cross-musl + extract-vmlinux)"
```

---

### Task 4: `extract_vmlinux(container, …)`

**Files:**
- Modify: `src/likedbg/foreign.py`
- Test: `tests/test_foreign.py`

**Interfaces:**
- Consumes: `ContainerService` (duck-typed via a fake), `constants.MUSL_IMAGE`.
- Produces: `foreign.extract_vmlinux(container, image_path: Path, out: Path, *, image: str) -> Path`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_foreign.py` (reuse the `FakeContainer` pattern from `tests/test_modules.py`):

```python
class _FakeContainer:
    def __init__(self, *, make_out: Path | None = None, out_bytes: bytes = b"\x7fELF") -> None:
        self.run_kwargs: dict | None = None
        self.execs: list[str] = []
        self.stopped = False
        self._make_out = make_out
        self._out_bytes = out_bytes

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return "CID"

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        if self._make_out is not None:  # simulate the container writing the output file
            self._make_out.write_bytes(self._out_bytes)
        return type("R", (), {"exit_code": 0, "output": ""})()

    def stop(self, container):
        self.stopped = True


def test_extract_vmlinux_runs_script_and_returns_out(tmp_path: Path) -> None:
    from likedbg.foreign import extract_vmlinux

    image_path = tmp_path / "in" / "bzImage"
    image_path.parent.mkdir()
    image_path.write_bytes(b"MZfake-bzImage")
    out = tmp_path / "out" / "vmlinux"
    c = _FakeContainer(make_out=out)

    result = extract_vmlinux(c, image_path, out, image="like_musl:latest")

    assert result == out and out.is_file()
    assert c.run_kwargs["image"] == "like_musl:latest"
    vols = c.run_kwargs["volumes"]
    assert vols[str(image_path.parent)] == {"bind": "/in", "mode": "ro"}
    assert vols[str(out.parent)] == {"bind": "/out", "mode": "rw"}
    assert "/opt/extract-vmlinux.sh /in/bzImage /out/vmlinux" in " ".join(c.execs)
    assert c.stopped is True


def test_extract_vmlinux_missing_output_raises(tmp_path: Path) -> None:
    from likedbg.foreign import extract_vmlinux

    image_path = tmp_path / "in" / "Image"
    image_path.parent.mkdir()
    image_path.write_bytes(b"arm64-Image")
    out = tmp_path / "out" / "vmlinux"
    c = _FakeContainer(make_out=None)  # container "produces" nothing
    with pytest.raises(ForeignError, match="could not extract vmlinux"):
        extract_vmlinux(c, image_path, out, image="like_musl:latest")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_foreign.py -k extract -v`
Expected: FAIL (`cannot import name 'extract_vmlinux'`).

- [ ] **Step 3: Implement**

Add to `src/likedbg/foreign.py`:

```python
from typing import Any


def extract_vmlinux(container: Any, image_path: Path, out: Path, *, image: str) -> Path:
    """Carve an uncompressed vmlinux ELF from a boot image inside the like_musl container.

    Returns `out` on success. Note: a vmlinux carved from a bzImage is fully stripped
    (kallsyms only, no ELF .symtab) — good for arch-detect, but gdb gets no function symbols
    (see ADR-0010). Raises ForeignError if extraction produces no file.
    """
    out.parent.mkdir(parents=True, exist_ok=True)
    c = container.run_detached(
        image,
        volumes={
            str(image_path.parent): {"bind": "/in", "mode": "ro"},
            str(out.parent): {"bind": "/out", "mode": "rw"},
        },
        detach=True,
        tty=True,
    )
    try:
        container.exec(c, f"/opt/extract-vmlinux.sh /in/{image_path.name} /out/{out.name}")
    finally:
        container.stop(c)
    if not out.is_file() or out.stat().st_size == 0:
        raise ForeignError(
            f"could not extract vmlinux from {image_path}",
            remedy="provide [foreign].vmlinux explicitly (arm64 Image / unknown compression)",
        )
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_foreign.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/foreign.py && uv run mypy src/likedbg
git add src/likedbg/foreign.py tests/test_foreign.py
git commit -m "feat(foreign): extract_vmlinux carves vmlinux in the like_musl container"
```

---

### Task 5: `resolve_input_path` + `resolve_foreign(container, …)`

**Files:**
- Modify: `src/likedbg/foreign.py`
- Test: `tests/test_foreign.py`

**Interfaces:**
- Consumes: `config.ForeignCfg`, `foreign.detect_arch`, `foreign.extract_vmlinux`, `foreign.ForeignKernel`.
- Produces:
  - `foreign.resolve_input_path(workspace: Path, raw: str) -> Path` — absolute stays absolute; relative resolves under `workspace`.
  - `foreign.resolve_foreign(container, cfg: ForeignCfg, workspace: Path, *, out_dir: Path, image: str) -> ForeignKernel`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_foreign.py`:

```python
def test_resolve_input_path_absolute_and_relative(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_input_path

    assert resolve_input_path(tmp_path, "/abs/x") == Path("/abs/x")
    assert resolve_input_path(tmp_path, "ctf/lk01/bzImage") == tmp_path / "ctf/lk01/bzImage"


def _mk_cfg(**kw):
    from likedbg.config import ForeignCfg

    return ForeignCfg(**kw)


def test_resolve_foreign_uses_provided_vmlinux_and_detects_arch(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_foreign

    (tmp_path / "bzImage").write_bytes(b"MZ")
    (tmp_path / "vmlinux").write_bytes(_elf_header(b"\x3e\x00"))  # x86_64
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    cfg = _mk_cfg(image="bzImage", vmlinux="vmlinux", initramfs="initramfs.cpio.gz", cmdline="quiet")
    c = _FakeContainer(make_out=None)

    fk = resolve_foreign(c, cfg, tmp_path, out_dir=tmp_path / "stage", image="like_musl:latest")

    assert fk.arch == "x86_64"
    assert fk.image == tmp_path / "bzImage"
    assert fk.vmlinux == tmp_path / "vmlinux"
    assert fk.initramfs == tmp_path / "initramfs.cpio.gz"
    assert fk.cmdline == "quiet"
    assert c.run_kwargs is None  # no extraction when vmlinux provided


def test_resolve_foreign_extracts_vmlinux_when_absent(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_foreign

    (tmp_path / "bzImage").write_bytes(b"MZ")
    staged = tmp_path / "stage" / "vmlinux"
    c = _FakeContainer(make_out=staged, out_bytes=_elf_header(b"\x3e\x00"))
    cfg = _mk_cfg(image="bzImage", cmdline="quiet")

    fk = resolve_foreign(c, cfg, tmp_path, out_dir=tmp_path / "stage", image="like_musl:latest")

    assert fk.vmlinux == staged and fk.arch == "x86_64"
    assert c.run_kwargs is not None  # extraction ran


def test_resolve_foreign_arch_override_skips_detection(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_foreign

    (tmp_path / "Image").write_bytes(b"arm64-Image")
    (tmp_path / "vmlinux").write_bytes(b"not-an-elf")  # would fail detect_arch
    cfg = _mk_cfg(image="Image", vmlinux="vmlinux", arch="arm64", cmdline="")
    c = _FakeContainer(make_out=None)

    fk = resolve_foreign(c, cfg, tmp_path, out_dir=tmp_path / "stage", image="like_musl:latest")
    assert fk.arch == "arm64"


def test_resolve_foreign_missing_image_raises(tmp_path: Path) -> None:
    from likedbg.foreign import resolve_foreign

    cfg = _mk_cfg(image="nope/bzImage")
    c = _FakeContainer(make_out=None)
    with pytest.raises(ForeignError, match="image"):
        resolve_foreign(c, cfg, tmp_path, out_dir=tmp_path / "stage", image="like_musl:latest")
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_foreign.py -k resolve -v`
Expected: FAIL (`cannot import name 'resolve_foreign'`).

- [ ] **Step 3: Implement**

Add to `src/likedbg/foreign.py`:

```python
def resolve_input_path(workspace: Path, raw: str) -> Path:
    """Absolute paths pass through; relative paths resolve under the workspace."""
    p = Path(raw)
    return p if p.is_absolute() else (workspace / p)


def resolve_foreign(
    container: Any,
    cfg: "ForeignCfg",
    workspace: Path,
    *,
    out_dir: Path,
    image: str,
) -> ForeignKernel:
    """Resolve foreign inputs, extract vmlinux if absent, detect arch, return a ForeignKernel.

    Called in cmd_foreign BEFORE resolve_for_run so the detected arch can be injected as a
    cli_override into HostProfile.detect (matching how cmd_use injects the cached build's arch).
    """
    image_path = resolve_input_path(workspace, cfg.image)
    if not image_path.is_file():
        raise ForeignError(
            f"[foreign].image not found: {image_path}",
            remedy="check the path (absolute or workspace-relative)",
        )

    if cfg.vmlinux:
        vmlinux = resolve_input_path(workspace, cfg.vmlinux)
        if not vmlinux.is_file():
            raise ForeignError(f"[foreign].vmlinux not found: {vmlinux}", remedy="check the path")
    else:
        vmlinux = extract_vmlinux(container, image_path, out_dir / "vmlinux", image=image)

    initramfs: Path | None = None
    if cfg.initramfs:
        initramfs = resolve_input_path(workspace, cfg.initramfs)
        if not initramfs.is_file():
            raise ForeignError(f"[foreign].initramfs not found: {initramfs}", remedy="check the path")

    arch = cfg.arch or detect_arch(vmlinux)
    if arch not in ("x86_64", "arm64"):
        raise ForeignError(f"invalid [foreign].arch {arch!r}", remedy="use x86_64 or arm64")

    return ForeignKernel(image=image_path, vmlinux=vmlinux, initramfs=initramfs, arch=arch, cmdline=cfg.cmdline)
```

Add `from likedbg.config import ForeignCfg` under a `TYPE_CHECKING` guard (or import directly — `config` does not import `foreign`, so no cycle). Prefer a direct import at top: `from likedbg.config import ForeignCfg` and drop the string annotation.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_foreign.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/foreign.py && uv run mypy src/likedbg
git add src/likedbg/foreign.py tests/test_foreign.py
git commit -m "feat(foreign): resolve_foreign (paths + vmlinux-extract + arch-detect)"
```

---

### Task 6: `repack_initramfs(container, …)`

**Files:**
- Modify: `src/likedbg/foreign.py`
- Test: `tests/test_foreign.py`

**Interfaces:**
- Consumes: `ContainerService` fake, `foreign.ForeignError`.
- Produces: `foreign.repack_initramfs(container, *, initramfs: Path, exploit: Path, arch: str, out: Path, image: str) -> Path`. A `.c` exploit is compiled `{x86_64,aarch64}-linux-musl-gcc -static`; anything else is copied as a prebuilt static binary. Injected at `/exploit`, repacked `newc` + gzip.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_foreign.py`:

```python
def test_repack_initramfs_compiles_c_with_cross_musl(tmp_path: Path) -> None:
    from likedbg.foreign import repack_initramfs

    initramfs = tmp_path / "in" / "initramfs.cpio.gz"
    initramfs.parent.mkdir()
    initramfs.write_bytes(b"\x1f\x8b")
    exploit = tmp_path / "src" / "exploit.c"
    exploit.parent.mkdir()
    exploit.write_text("int main(){return 0;}\n")
    out = tmp_path / "out" / "initramfs.repacked.cpio.gz"
    c = _FakeContainer(make_out=out, out_bytes=b"\x1f\x8b")

    result = repack_initramfs(
        c, initramfs=initramfs, exploit=exploit, arch="x86_64", out=out, image="like_musl:latest"
    )

    assert result == out
    cmd = " ".join(c.execs)
    assert "x86_64-linux-musl-gcc -static /src/exploit.c -o" in cmd
    assert "cpio --null --format=newc -o" in cmd and "gzip" in cmd
    vols = c.run_kwargs["volumes"]
    assert vols[str(initramfs.parent)]["mode"] == "ro"
    assert vols[str(out.parent)]["mode"] == "rw"


def test_repack_initramfs_arm64_uses_aarch64_gcc(tmp_path: Path) -> None:
    from likedbg.foreign import repack_initramfs

    initramfs = tmp_path / "in" / "rootfs.cpio"
    initramfs.parent.mkdir()
    initramfs.write_bytes(b"07070100")  # newc magic
    exploit = tmp_path / "src" / "pwn.c"
    exploit.parent.mkdir()
    exploit.write_text("int main(){}\n")
    out = tmp_path / "out" / "repacked.cpio"
    c = _FakeContainer(make_out=out, out_bytes=b"07070100")

    repack_initramfs(c, initramfs=initramfs, exploit=exploit, arch="arm64", out=out, image="like_musl:latest")
    assert "aarch64-linux-musl-gcc -static" in " ".join(c.execs)


def test_repack_initramfs_copies_prebuilt_binary(tmp_path: Path) -> None:
    from likedbg.foreign import repack_initramfs

    initramfs = tmp_path / "in" / "initramfs.cpio.gz"
    initramfs.parent.mkdir()
    initramfs.write_bytes(b"\x1f\x8b")
    exploit = tmp_path / "src" / "exploit"  # no .c suffix = prebuilt static binary
    exploit.parent.mkdir()
    exploit.write_bytes(b"\x7fELFstatic")
    out = tmp_path / "out" / "initramfs.repacked.cpio.gz"
    c = _FakeContainer(make_out=out, out_bytes=b"\x1f\x8b")

    repack_initramfs(c, initramfs=initramfs, exploit=exploit, arch="x86_64", out=out, image="like_musl:latest")
    cmd = " ".join(c.execs)
    assert "cp /src/exploit" in cmd and "musl-gcc" not in cmd
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_foreign.py -k repack -v`
Expected: FAIL (`cannot import name 'repack_initramfs'`).

- [ ] **Step 3: Implement**

Add to `src/likedbg/foreign.py` (import `shlex` at top):

```python
_MUSL_GCC = {"x86_64": "x86_64-linux-musl-gcc", "arm64": "aarch64-linux-musl-gcc"}


def _repack_command(initramfs_name: str, exploit_name: str, arch: str, out_name: str) -> str:
    if exploit_name.endswith(".c"):
        inject = f"{_MUSL_GCC[arch]} -static /src/{exploit_name} -o /work/rootfs/exploit"
    else:
        inject = f"cp /src/{exploit_name} /work/rootfs/exploit && chmod +x /work/rootfs/exploit"
    unpack = (
        f"if gzip -t /in/{initramfs_name} 2>/dev/null; "
        f"then gzip -dc /in/{initramfs_name} | cpio -idm; "
        f"else cpio -idm < /in/{initramfs_name}; fi"
    )
    repack = f"find . -print0 | cpio --null --format=newc -o --owner=root"
    if out_name.endswith(".gz"):
        repack += f" | gzip -9 > /out/{out_name}"
    else:
        repack += f" > /out/{out_name}"
    return " && ".join(["mkdir -p /work/rootfs", "cd /work/rootfs", unpack, inject, repack])


def repack_initramfs(
    container: Any,
    *,
    initramfs: Path,
    exploit: Path,
    arch: str,
    out: Path,
    image: str,
) -> Path:
    """Unpack the foreign initramfs, inject the exploit at /exploit (musl-static compile of a
    .c, else copy a prebuilt static binary), repack (newc [+gzip]) to `out` in the like_musl
    container. Compiling to the FOREIGN arch is why `arch` is threaded in."""
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = _repack_command(initramfs.name, exploit.name, arch, out.name)
    c = container.run_detached(
        image,
        volumes={
            str(initramfs.parent): {"bind": "/in", "mode": "ro"},
            str(exploit.parent): {"bind": "/src", "mode": "ro"},
            str(out.parent): {"bind": "/out", "mode": "rw"},
        },
        detach=True,
        tty=True,
    )
    try:
        container.exec(c, cmd)
    finally:
        container.stop(c)
    if not out.is_file():
        raise ForeignError(
            f"initramfs repack produced no output at {out}",
            remedy="check the exploit compiles and the cpio format round-trips",
        )
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_foreign.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/foreign.py && uv run mypy src/likedbg
git add src/likedbg/foreign.py tests/test_foreign.py
git commit -m "feat(foreign): repack_initramfs (cross-musl compile + inject /exploit + newc repack)"
```

---

### Task 7: QEMU foreign branch (`foreign_cmdline` + `qemu_extra`)

**Files:**
- Modify: `src/likedbg/qemu.py`
- Test: `tests/test_qemu.py`

**Interfaces:**
- Consumes: existing `build_qemu_argv` params, `_rootfs_args`.
- Produces: two new keyword params on `build_qemu_argv`: `foreign_cmdline: str | None = None`, `qemu_extra: tuple[str, ...] = ()`. When `foreign_cmdline is not None`: `-append` = the verbatim cmdline + `console=<dev>` (if absent) + `extra_boot_args` — NO mitigations/root/panic; `qemu_extra` is appended to the argv end. Existing (non-foreign) behavior is unchanged when both defaults hold.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_qemu.py`:

```python
def test_foreign_cmdline_used_verbatim_no_mitigations():
    argv = build_qemu_argv(
        _debuggee(kaslr=False),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=Path("/w/initramfs.cpio.gz"),
        foreign_cmdline="quiet console=ttyS0 kaslr",
    )
    append = argv[argv.index("-append") + 1]
    assert append.startswith("quiet console=ttyS0 kaslr")
    # no imposed mitigation/root/panic tokens
    for tok in ("nokaslr", "nosmep", "nosmap", "pti=on", "root=/dev/ram", "oops=panic", "panic="):
        assert tok not in append


def test_foreign_cmdline_adds_console_when_missing():
    argv = build_qemu_argv(
        _debuggee(),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline="quiet",
    )
    append = argv[argv.index("-append") + 1]
    assert "console=ttyS0" in append


def test_foreign_cmdline_arm64_console_ttyama0():
    argv = build_qemu_argv(
        _debuggee(),
        _host(target_arch="arm64"),
        target_arch="arm64",
        kernel_image=Path("/w/Image"),
        rootfs=None,
        foreign_cmdline="quiet",
    )
    append = argv[argv.index("-append") + 1]
    assert "console=ttyAMA0" in append


def test_foreign_cmdline_layers_extra_boot_args():
    argv = build_qemu_argv(
        _debuggee(),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline="quiet console=ttyS0",
        extra_boot_args=("nokaslr",),
    )
    append = argv[argv.index("-append") + 1]
    assert append.endswith("nokaslr")


def test_foreign_initramfs_uses_initrd_and_gdbstub():
    argv = build_qemu_argv(
        _debuggee(gdb=True),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=Path("/w/initramfs.cpio.gz"),
        foreign_cmdline="quiet console=ttyS0",
    )
    s = _argstr(argv)
    assert "-initrd /w/initramfs.cpio.gz" in s
    assert "-S" in argv and "tcp::1234" in argv


def test_qemu_extra_appended_to_argv():
    argv = build_qemu_argv(
        _debuggee(),
        _host(target_arch="x86_64"),
        target_arch="x86_64",
        kernel_image=Path("/w/bzImage"),
        rootfs=None,
        foreign_cmdline="quiet console=ttyS0",
        qemu_extra=("-no-reboot", "-monitor", "none"),
    )
    s = _argstr(argv)
    assert "-no-reboot" in argv and "-monitor" in argv and "none" in argv
    # appears after the gdbstub block
    assert argv.index("-no-reboot") > argv.index("-gdb")


def test_qemu_extra_empty_by_default_keeps_existing_argv():
    argv = build_qemu_argv(
        _debuggee(), _host(), target_arch="arm64", kernel_image=Path("/w/Image"), rootfs=None
    )
    assert "nokaslr" in argv[argv.index("-append") + 1]  # normal path unchanged
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_qemu.py -k "foreign or qemu_extra" -v`
Expected: FAIL (`build_qemu_argv() got an unexpected keyword argument 'foreign_cmdline'`).

- [ ] **Step 3: Implement**

In `src/likedbg/qemu.py`, add a helper above `build_qemu_argv`:

```python
def _foreign_append(cmdline: str, console_dev: str, extra_boot_args: tuple[str, ...]) -> str:
    parts = [cmdline]
    if "console=" not in cmdline:
        parts.append(f"console={console_dev}")
    parts.extend(extra_boot_args)
    return " ".join(p for p in parts if p)
```

Extend the signature (add the two params at the end of the keyword-only block):

```python
    foreign_cmdline: str | None = None,
    qemu_extra: tuple[str, ...] = (),
```

Capture the console device name in each arch branch. Change the arm64 branch's `console = "console=ttyAMA0"` line to also set `console_dev = "ttyAMA0"`, and the x86 branch's `console = "console=ttyS0"` to also set `console_dev = "ttyS0"`. Then replace the `append = " ".join([...])` assembly (lines ~67-78) with:

```python
    drive_args, root = _rootfs_args(rootfs)
    if foreign_cmdline is not None:
        append = _foreign_append(foreign_cmdline, console_dev, extra_boot_args)
    else:
        append = " ".join(
            [
                console,
                root,
                "earlyprintk=serial",
                "net.ifnames=0",
                *_mitigations(debuggee),
                *extra_boot_args,
                "oops=panic",
                _panic(debuggee),
            ]
        )
```

Finally, before `return argv` (after the gdbstub block, line ~97), append:

```python
    argv += list(qemu_extra)
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_qemu.py -q`
Expected: PASS (both new tests and the existing suite — `qemu_extra` defaults to `()` so normal argv is unchanged).

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/qemu.py && uv run mypy src/likedbg
git add src/likedbg/qemu.py tests/test_qemu.py
git commit -m "feat(foreign): build_qemu_argv foreign branch (verbatim cmdline + qemu_extra, no mitigations)"
```

---

### Task 8: `PipelineContext` fields + `DebuggeeStage` wiring

**Files:**
- Modify: `src/likedbg/pipeline.py`, `src/likedbg/stages/debuggee.py`
- Test: `tests/test_stage_debuggee.py`

**Interfaces:**
- Consumes: `PipelineContext`, `DebuggeeStage`, `build_qemu_argv` (from Task 7).
- Produces: `PipelineContext.foreign_cmdline: str | None = None`, `PipelineContext.qemu_extra: tuple[str, ...] = ()`; `DebuggeeStage.run` passes `foreign_cmdline=ctx.foreign_cmdline, qemu_extra=ctx.qemu_extra` into `build_qemu_argv`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_stage_debuggee.py` (mirror the existing monkeypatch-capture test at lines ~148-162):

```python
def test_debuggee_threads_foreign_cmdline_and_qemu_extra(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "likedbg.stages.debuggee.build_qemu_argv",
        lambda *a, **k: captured.update(k) or ["qemu-system-x86_64"],
    )
    ctx = _ctx("native-host")
    ctx.foreign_cmdline = "quiet console=ttyS0"
    ctx.qemu_extra = ("-no-reboot",)
    DebuggeeStage(
        launch=lambda cmd: None, debuggee_image="like_debuggee:latest", workspace=tmp_path
    ).run(ctx)
    assert captured["foreign_cmdline"] == "quiet console=ttyS0"
    assert captured["qemu_extra"] == ("-no-reboot",)
```

(If the local `_ctx` helper in that test file builds a `PipelineContext` with `kernel_image` set, reuse it; otherwise set `ctx.kernel_image = Path("/w/bzImage")` before `.run`.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_stage_debuggee.py -k foreign -v`
Expected: FAIL (`AttributeError: 'PipelineContext' object has no attribute 'foreign_cmdline'`).

- [ ] **Step 3: Implement**

In `src/likedbg/pipeline.py`, add to the `PipelineContext` dataclass (after `extra_boot_args`, keeping all-defaulted so it stays non-breaking):

```python
    foreign_cmdline: str | None = None
    qemu_extra: tuple[str, ...] = field(default_factory=tuple)
```

In `src/likedbg/stages/debuggee.py`, extend the `build_qemu_argv(...)` call (after `share_host_dir=share_host_dir,`):

```python
            foreign_cmdline=ctx.foreign_cmdline,
            qemu_extra=ctx.qemu_extra,
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_stage_debuggee.py tests/test_pipeline.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg && uv run mypy src/likedbg
git add src/likedbg/pipeline.py src/likedbg/stages/debuggee.py tests/test_stage_debuggee.py
git commit -m "feat(foreign): thread foreign_cmdline + qemu_extra through PipelineContext/DebuggeeStage"
```

---

### Task 9: `ForeignAdoptStage`

**Files:**
- Create: `src/likedbg/stages/foreign.py`
- Test: `tests/test_stage_foreign.py`

**Interfaces:**
- Consumes: `pipeline.PipelineContext`, `foreign.ForeignKernel`, `constants.VOLUME_MOUNT`.
- Produces: `stages.foreign.ForeignAdoptStage` — `name = "foreign-adopt"`; constructor `ForeignAdoptStage(*, foreign: ForeignKernel, qemu_extra: tuple[str, ...])`. `run` sets `ctx.kernel_image = foreign.image`, `ctx.rootfs_image = foreign.initramfs`, `ctx.vmlinux = Path(VOLUME_MOUNT) / foreign.vmlinux.name` (the in-container gdb path), `ctx.foreign_cmdline = foreign.cmdline`, `ctx.qemu_extra = qemu_extra`, and calls `ctx.recorder.record_kernel_paths(config=None, system_map="", vmlinux=<host vmlinux>, image=<host image>)` when a recorder is present. `should_skip` returns `False`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_stage_foreign.py`:

```python
from pathlib import Path

from likedbg.config import Settings
from likedbg.foreign import ForeignKernel
from likedbg.pipeline import PipelineContext
from likedbg.stages.foreign import ForeignAdoptStage


class _Rec:
    def __init__(self):
        self.kernel_paths = None

    def record_kernel_paths(self, *, config, system_map, vmlinux, image):
        self.kernel_paths = {"config": config, "system_map": system_map, "vmlinux": vmlinux, "image": image}


def _host(target_arch="x86_64"):
    from likedbg.host_profile import HostProfile

    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch=target_arch,
        accel="tcg",
        debuggee_mode="in-container",
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )


def _fk(tmp_path):
    return ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=tmp_path / "initramfs.cpio.gz",
        arch="x86_64",
        cmdline="quiet console=ttyS0",
    )


def test_foreign_adopt_sets_ctx_fields(tmp_path):
    ctx = PipelineContext(settings=Settings(), host=_host())
    ForeignAdoptStage(foreign=_fk(tmp_path), qemu_extra=("-no-reboot",)).run(ctx)
    assert ctx.kernel_image == tmp_path / "bzImage"
    assert ctx.rootfs_image == tmp_path / "initramfs.cpio.gz"
    assert ctx.vmlinux == Path("/ksrc/vmlinux")  # in-container gdb path
    assert ctx.foreign_cmdline == "quiet console=ttyS0"
    assert ctx.qemu_extra == ("-no-reboot",)


def test_foreign_adopt_records_kernel_paths_config_none(tmp_path):
    ctx = PipelineContext(settings=Settings(), host=_host())
    rec = _Rec()
    ctx.recorder = rec
    ForeignAdoptStage(foreign=_fk(tmp_path), qemu_extra=()).run(ctx)
    assert rec.kernel_paths["config"] is None
    assert rec.kernel_paths["vmlinux"] == str(tmp_path / "vmlinux")
    assert rec.kernel_paths["image"] == str(tmp_path / "bzImage")


def test_foreign_adopt_does_not_skip(tmp_path):
    ctx = PipelineContext(settings=Settings(), host=_host())
    assert ForeignAdoptStage(foreign=_fk(tmp_path), qemu_extra=()).should_skip(ctx) is False
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_stage_foreign.py -v`
Expected: FAIL (`No module named 'likedbg.stages.foreign'`).

- [ ] **Step 3: Implement**

Create `src/likedbg/stages/foreign.py`:

```python
"""Foreign-kernel pipeline stages: adopt a provided kernel (Manifest-free) and optionally
repack its initramfs with an exploit. See ADR-0010."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from likedbg.constants import VOLUME_MOUNT
from likedbg.foreign import ForeignKernel
from likedbg.foreign import repack_initramfs
from likedbg.pipeline import PipelineContext


class ForeignAdoptStage:
    """Inject a pre-resolved ForeignKernel into the ctx (no Manifest, no .config)."""

    name = "foreign-adopt"

    def __init__(self, *, foreign: ForeignKernel, qemu_extra: tuple[str, ...]) -> None:
        self._foreign = foreign
        self._qemu_extra = qemu_extra

    def should_skip(self, ctx: PipelineContext) -> bool:
        return False

    def run(self, ctx: PipelineContext) -> PipelineContext:
        fk = self._foreign
        ctx.kernel_image = fk.image
        ctx.rootfs_image = fk.initramfs
        # gdb mounts the vmlinux's host dir at VOLUME_MOUNT (/ksrc) read-only; the in-container
        # path is /ksrc/<basename>. The mount source is passed to build_foreign_pipeline.
        ctx.vmlinux = Path(VOLUME_MOUNT) / fk.vmlinux.name
        ctx.foreign_cmdline = fk.cmdline
        ctx.qemu_extra = self._qemu_extra
        if ctx.recorder is not None:
            ctx.recorder.record_kernel_paths(  # type: ignore[attr-defined]
                config=None,
                system_map="",
                vmlinux=str(fk.vmlinux),
                image=str(fk.image),
            )
        return ctx
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_stage_foreign.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/stages/foreign.py && uv run mypy src/likedbg
git add src/likedbg/stages/foreign.py tests/test_stage_foreign.py
git commit -m "feat(foreign): ForeignAdoptStage (Manifest-free ctx inject + record_kernel_paths)"
```

---

### Task 10: `ForeignRepackStage`

**Files:**
- Modify: `src/likedbg/stages/foreign.py`
- Test: `tests/test_stage_foreign.py`

**Interfaces:**
- Consumes: `foreign.repack_initramfs`, `ForeignKernel`.
- Produces: `stages.foreign.ForeignRepackStage` — `name = "foreign-repack"`; constructor `ForeignRepackStage(container, *, foreign: ForeignKernel, exploit: Path | None, image: str, out_dir: Path)`. `should_skip` returns `True` when `exploit is None`. `run` calls `repack_initramfs(container, initramfs=foreign.initramfs, exploit=exploit, arch=ctx.host.target_arch, out=out_dir/"initramfs.repacked.cpio.gz", image=image)` and repoints `ctx.rootfs_image` at the result.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_stage_foreign.py`:

```python
from likedbg.stages.foreign import ForeignRepackStage


class _RepackFakeContainer:
    def __init__(self, out: Path):
        self.execs = []
        self.run_kwargs = None
        self._out = out

    def run_detached(self, image, **kwargs):
        self.run_kwargs = {"image": image, **kwargs}
        return "CID"

    def exec(self, container, cmd, *, workdir=None):
        self.execs.append(cmd)
        self._out.parent.mkdir(parents=True, exist_ok=True)
        self._out.write_bytes(b"\x1f\x8b")
        return type("R", (), {"exit_code": 0, "output": ""})()

    def stop(self, container):
        pass


def test_foreign_repack_skips_without_exploit(tmp_path):
    ctx = PipelineContext(settings=Settings(), host=_host())
    stage = ForeignRepackStage(
        _RepackFakeContainer(tmp_path / "x"),
        foreign=_fk(tmp_path),
        exploit=None,
        image="like_musl:latest",
        out_dir=tmp_path / "stage",
    )
    assert stage.should_skip(ctx) is True


def test_foreign_repack_repoints_rootfs(tmp_path):
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    exploit = tmp_path / "exploit.c"
    exploit.write_text("int main(){}\n")
    out = tmp_path / "stage" / "initramfs.repacked.cpio.gz"
    c = _RepackFakeContainer(out)
    ctx = PipelineContext(settings=Settings(), host=_host())
    ForeignAdoptStage(foreign=_fk(tmp_path), qemu_extra=()).run(ctx)  # sets rootfs to the raw initramfs
    stage = ForeignRepackStage(
        c, foreign=_fk(tmp_path), exploit=exploit, image="like_musl:latest", out_dir=tmp_path / "stage"
    )
    assert stage.should_skip(ctx) is False
    stage.run(ctx)
    assert ctx.rootfs_image == out
    assert "x86_64-linux-musl-gcc -static" in " ".join(c.execs)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_stage_foreign.py -k repack -v`
Expected: FAIL (`cannot import name 'ForeignRepackStage'`).

- [ ] **Step 3: Implement**

Add to `src/likedbg/stages/foreign.py`:

```python
class ForeignRepackStage:
    """Repack the foreign initramfs with the exploit at /exploit; runs only when exploit is set."""

    name = "foreign-repack"

    def __init__(
        self,
        container: Any,
        *,
        foreign: ForeignKernel,
        exploit: Path | None,
        image: str,
        out_dir: Path,
    ) -> None:
        self._c = container
        self._foreign = foreign
        self._exploit = exploit
        self._image = image
        self._out_dir = out_dir

    def should_skip(self, ctx: PipelineContext) -> bool:
        return self._exploit is None or self._foreign.initramfs is None

    def run(self, ctx: PipelineContext) -> PipelineContext:
        assert self._exploit is not None and self._foreign.initramfs is not None
        repacked = repack_initramfs(
            self._c,
            initramfs=self._foreign.initramfs,
            exploit=self._exploit,
            arch=ctx.host.target_arch,
            out=self._out_dir / "initramfs.repacked.cpio.gz",
            image=self._image,
        )
        ctx.rootfs_image = repacked
        return ctx
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_stage_foreign.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/stages/foreign.py && uv run mypy src/likedbg
git add src/likedbg/stages/foreign.py tests/test_stage_foreign.py
git commit -m "feat(foreign): ForeignRepackStage (repack initramfs, repoint rootfs)"
```

---

### Task 11: `build_foreign_pipeline`

**Files:**
- Modify: `src/likedbg/cli.py`
- Test: `tests/test_cli_foreign.py`

**Interfaces:**
- Consumes: `Pipeline`, `ForeignAdoptStage`, `ForeignRepackStage`, `DebuggeeStage`, `DebuggerStage`, `gdb_pane_command`, `Session`, `HostProfile`, `ForeignKernel`.
- Produces: `cli.build_foreign_pipeline(container, session, *, host, workspace, foreign: ForeignKernel, exploit: Path | None, qemu_extra: tuple[str, ...], gdb_mount_source: str, out_dir: Path, debugger_image, debuggee_image, ext, musl_image, recorder=None, break_on_crash=False, crash_breakpoints=()) -> Pipeline`. Stage order: `foreign-adopt → foreign-repack → debuggee → debugger` (repack self-skips when no exploit). It builds the same `launch_debuggee`/`run_gdb` tmux closures as `build_use_pipeline`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_foreign.py`:

```python
from pathlib import Path

from likedbg.cli import build_foreign_pipeline
from likedbg.container_service import ContainerService
from likedbg.foreign import ForeignKernel
from likedbg.host_profile import HostProfile


def _host(mode="in-container", target_arch="x86_64"):
    return HostProfile(
        os="darwin",
        host_arch="arm64",
        target_arch=target_arch,
        accel="tcg",
        debuggee_mode=mode,
        storage_mode="volume",
        gdbstub_addr="host.docker.internal",
    )


class _FakeSession:
    def __init__(self):
        self.options = {}
        self._panes = iter(["%2", "%3"])

    def current_pane_id(self):
        return "%1"

    def unset_option(self, k):
        pass

    def set_option(self, k, v):
        self.options[k] = v

    def run_in_new_pane(self, *, target, direction, percent, cmd):
        return next(self._panes)

    def pipe_pane(self, *, pane, output):
        pass


class _FakeContainer(ContainerService):
    def __init__(self):
        pass


def _fk(tmp_path):
    (tmp_path / "bzImage").write_bytes(b"MZ")
    (tmp_path / "vmlinux").write_bytes(b"\x7fELF")
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    return ForeignKernel(
        image=tmp_path / "bzImage",
        vmlinux=tmp_path / "vmlinux",
        initramfs=tmp_path / "initramfs.cpio.gz",
        arch="x86_64",
        cmdline="quiet console=ttyS0",
    )


def test_build_foreign_pipeline_stage_order(tmp_path):
    pipe = build_foreign_pipeline(
        _FakeContainer(),
        _FakeSession(),  # type: ignore[arg-type]
        host=_host(),
        workspace=tmp_path,
        foreign=_fk(tmp_path),
        exploit=None,
        qemu_extra=(),
        gdb_mount_source=str(tmp_path),
        out_dir=tmp_path / "stage",
        debugger_image="like_debugger:latest",
        debuggee_image="like_debuggee:latest",
        ext="pwndbg",
        musl_image="like_musl:latest",
        recorder=None,
    )
    assert [s.name for s in pipe._stages] == [  # type: ignore[attr-defined]
        "foreign-adopt",
        "foreign-repack",
        "debuggee",
        "debugger",
    ]
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_cli_foreign.py -k stage_order -v`
Expected: FAIL (`cannot import name 'build_foreign_pipeline'`).

- [ ] **Step 3: Implement**

In `src/likedbg/cli.py`, import the new stages near the other stage imports:

```python
from likedbg.stages.foreign import ForeignAdoptStage
from likedbg.stages.foreign import ForeignRepackStage
from likedbg.foreign import ForeignKernel
```

Add `build_foreign_pipeline` right after `build_use_pipeline`. Reuse the exact `base_pane` / `launch_debuggee` / `run_gdb` closure block from `build_use_pipeline` (copy it verbatim — the tmux wiring is identical), then return the foreign stage list:

```python
def build_foreign_pipeline(
    container: ContainerService,
    session: Session,
    *,
    host: HostProfile,
    workspace: Path,
    foreign: ForeignKernel,
    exploit: Path | None,
    qemu_extra: tuple[str, ...],
    gdb_mount_source: str,
    out_dir: Path,
    debugger_image: str,
    debuggee_image: str,
    ext: str,
    musl_image: str,
    recorder: RunRecorder | None = None,
    break_on_crash: bool = False,
    crash_breakpoints: tuple[str, ...] = (),
) -> Pipeline:
    base_pane = session.current_pane_id()
    debuggee_pane: str | None = None

    for opt in _SESSION_STATE_OPTIONS:
        session.unset_option(opt)
    session.set_option("@likedbg_workspace", str(workspace))
    session.set_option("@likedbg_base_pane_id", base_pane)

    def launch_debuggee(cmd: str) -> None:
        nonlocal debuggee_pane
        session.set_option("@likedbg_debuggee_cmd", cmd)
        debuggee_pane = session.run_in_new_pane(target=base_pane, direction="h", percent=66, cmd=cmd)
        session.set_option("@likedbg_debuggee_pane", debuggee_pane)
        if recorder is not None:
            session.set_option("@likedbg_debuggee_pane_log", str(recorder.debuggee_pane_log))
            try:
                session.pipe_pane(pane=debuggee_pane, output=recorder.debuggee_pane_log)
            except LikeDbgError as exc:
                recorder.add_warning("transcript-capture-failed", f"pipe-pane failed for Debuggee: {exc}")

    def run_gdb(args: list[str]) -> None:
        if debuggee_pane is None:
            raise RuntimeError("debuggee pane has not been launched")
        cmd = gdb_pane_command(
            args,
            image=debugger_image,
            mount_source=gdb_mount_source,
            network_mode=host.network_mode,
            crash_drop=recorder.crash_dir if recorder is not None else None,
        )
        session.set_option("@likedbg_debugger_cmd", cmd)
        debugger_pane = session.run_in_new_pane(target=debuggee_pane, direction="v", percent=50, cmd=cmd)
        session.set_option("@likedbg_debugger_pane", debugger_pane)
        if recorder is not None:
            try:
                session.pipe_pane(pane=debugger_pane, output=recorder.debugger_pane_log)
            except LikeDbgError as exc:
                recorder.add_warning("transcript-capture-failed", f"pipe-pane failed for Debugger: {exc}")

    return Pipeline(
        [
            ForeignAdoptStage(foreign=foreign, qemu_extra=qemu_extra),
            ForeignRepackStage(
                container, foreign=foreign, exploit=exploit, image=musl_image, out_dir=out_dir
            ),
            DebuggeeStage(launch=launch_debuggee, debuggee_image=debuggee_image, workspace=workspace),
            DebuggerStage(
                ext=ext,
                run_gdb=run_gdb,
                breakpoint="start_kernel",
                break_on_crash=break_on_crash,
                crash_breakpoints=crash_breakpoints,
            ),
        ]
    )
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_cli_foreign.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/cli.py && uv run mypy src/likedbg
git add src/likedbg/cli.py tests/test_cli_foreign.py
git commit -m "feat(foreign): build_foreign_pipeline (adopt -> repack -> debuggee -> debugger)"
```

---

### Task 12: `cmd_foreign` + `main` dispatch

**Files:**
- Modify: `src/likedbg/cli.py`
- Test: `tests/test_cli_foreign.py`

**Interfaces:**
- Consumes: `load_config`, `resolve_foreign`, `resolve_for_run`, `_ensure_images`, `images.foreign_prep_images`/`required_for_foreign`, `RunRecorder.start`, `PipelineContext`, `build_foreign_pipeline`, `constants.MUSL_IMAGE`.
- Produces: `cli.cmd_foreign(container, session, workspace, *, scenario: Path | None, profile_arg: str = "") -> int`; a dispatch guard in `main` (before `if args.use:`) that returns `cmd_foreign(...)` when `cfg.settings.foreign.image` is set.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_cli_foreign.py` (mirror the `cmd_use` monkeypatch recipe from `tests/test_cli.py`):

```python
import types

from likedbg import cli
from likedbg.config import Settings


class _FakeRecorder:
    def __init__(self, workspace):
        self.likedbg_log = workspace / "log"
        self.debuggee_pane_log = workspace / "d.log"
        self.debugger_pane_log = workspace / "g.log"
        self.crash_dir = workspace / "crash"

    def record_kernel_paths(self, **kw):
        pass


def _write_project(tmp_path):
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "default.toml").write_text('[general]\narch = "native"\n')
    (tmp_path / "bzImage").write_bytes(b"MZ")
    (tmp_path / "vmlinux").write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00" + b"\x3e\x00" + b"\x00" * 20
    )
    (tmp_path / "initramfs.cpio.gz").write_bytes(b"\x1f\x8b")
    sc = tmp_path / "configs" / "scenarios"
    sc.mkdir()
    (sc / "lk01.toml").write_text(
        '[foreign]\nimage = "bzImage"\nvmlinux = "vmlinux"\n'
        'initramfs = "initramfs.cpio.gz"\ncmdline = "quiet console=ttyS0"\n'
    )
    return sc / "lk01.toml"


def test_cmd_foreign_runs_pipeline(tmp_path, monkeypatch):
    scenario = _write_project(tmp_path)
    ran = {}

    monkeypatch.setattr(cli, "_ensure_images", lambda container, workspace, *, specs: None)
    monkeypatch.setattr(cli.HostProfile, "detect", staticmethod(lambda s, workspace: _host()))
    monkeypatch.setattr(cli.logsetup, "add_run_logfile", lambda workspace, **kw: None)
    monkeypatch.setattr(
        cli.RunRecorder,
        "start",
        staticmethod(
            lambda *, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles: (
                _FakeRecorder(workspace)
            )
        ),
    )

    class _Pipe:
        def run(self, ctx):
            ran["ctx"] = ctx

    monkeypatch.setattr(cli, "build_foreign_pipeline", lambda *a, **k: _Pipe())

    rc = cli.cmd_foreign(_FakeContainer(), _FakeSession(), tmp_path, scenario=scenario)
    assert rc == 0
    assert ran["ctx"].host.target_arch == "x86_64"  # arch injected from the vmlinux ELF


def test_main_dispatches_to_cmd_foreign_when_image_set(tmp_path, monkeypatch):
    scenario = _write_project(tmp_path)
    called = {}
    monkeypatch.setattr(cli, "cmd_foreign", lambda *a, **k: called.setdefault("hit", True) or 0)
    monkeypatch.setattr(cli.os, "getenv", lambda k, d=None: "1" if k == "TMUX" else d)
    monkeypatch.setattr(cli.docker_env, "make_client", lambda **k: object())
    monkeypatch.setattr(cli, "ContainerService", lambda client: _FakeContainer())
    monkeypatch.setattr(cli.Path, "cwd", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(cli.Session, "start", lambda self, name: None)
    rc = cli.main(["-c", "lk01"])
    assert called.get("hit") and rc == 0
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_cli_foreign.py -k "cmd_foreign or dispatch" -v`
Expected: FAIL (`module 'likedbg.cli' has no attribute 'cmd_foreign'`).

- [ ] **Step 3: Implement**

In `src/likedbg/cli.py`, add `cmd_foreign` after `cmd_use`:

```python
def cmd_foreign(
    container: ContainerService,
    session: Session,
    workspace: Path,
    *,
    scenario: Path | None,
    profile_arg: str = "",
) -> int:
    cfg0 = load_config(workspace, scenario=scenario)
    fcfg = cfg0.settings.foreign
    if not fcfg.image:
        raise ForeignError("no [foreign].image configured", remedy="set [foreign].image in your scenario")

    name = scenario.stem if scenario is not None else "foreign"
    out_dir = workspace / "artifacts" / "foreign" / name
    # musl (+ base) must exist before we can extract vmlinux / repack.
    _ensure_images(container, workspace, specs=images.foreign_prep_images())
    fk = resolve_foreign(container, fcfg, workspace, out_dir=out_dir, image=MUSL_IMAGE)

    # Inject the detected arch so HostProfile.detect / QEMU / gdb follow the foreign kernel.
    cfg, host, rr = resolve_for_run(
        workspace,
        profile_arg=profile_arg,
        scenario=scenario,
        cli_overrides={"general": {"arch": fk.arch}},
    )
    _ensure_images(container, workspace, specs=images.required_for_foreign(host))

    exploit = resolve_input_path(workspace, fcfg.exploit) if fcfg.exploit else None
    if exploit is not None and not exploit.is_file():
        raise ForeignError(f"[foreign].exploit not found: {exploit}", remedy="check the path")

    recorder = RunRecorder.start(
        workspace=workspace,
        requested_settings=cfg.settings,
        run_resolution=rr,
        host=host,
        build_label=f"foreign-{name}",
        rootfs_label="",
        profiles=rr.profiles,
    )
    logsetup.add_run_logfile(workspace, path=recorder.likedbg_log)

    ctx = PipelineContext(
        settings=cfg.settings,
        host=host,
        effective_debuggee=rr.effective_debuggee,
        extra_boot_args=rr.extra_boot_args,
        recorder=recorder,
    )
    pipeline = build_foreign_pipeline(
        container,
        session,
        host=host,
        workspace=workspace,
        foreign=fk,
        exploit=exploit,
        qemu_extra=fcfg.qemu_extra,
        gdb_mount_source=str(fk.vmlinux.parent),
        out_dir=out_dir,
        debugger_image=DEBUGGER_IMAGE,
        debuggee_image=DEBUGGEE_IMAGE,
        ext=cfg.settings.debugger.ext,
        musl_image=MUSL_IMAGE,
        recorder=recorder,
        break_on_crash=cfg.settings.debugger.break_on_crash,
        crash_breakpoints=cfg.settings.debugger.crash_breakpoints,
    )
    pipeline.run(ctx)
    return 0
```

Add imports near the top of `cli.py`: `from likedbg.foreign import ForeignError`, `from likedbg.foreign import resolve_foreign`, `from likedbg.foreign import resolve_input_path`, `from likedbg.constants import MUSL_IMAGE`.

Add the dispatch in `main`, immediately **before** `if args.use:` (line ~813 — `cfg` from the earlier `load_config` at line ~799 is in scope):

```python
        if cfg.settings.foreign.image:
            if not os.getenv("TMUX"):
                logger.error("Not running inside a TMUX session. Start tmux first.")
                return 2
            session = Session("LIKE-DBG")
            session.start("LIKE-DBG")
            return cmd_foreign(
                container,
                session,
                workspace,
                scenario=_scenario_path(workspace, args.config),
                profile_arg=args.profile,
            )
```

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_cli_foreign.py tests/test_cli.py -q`
Expected: PASS (existing cli tests still green — the dispatch only fires when `foreign.image` is set).

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg/cli.py && uv run mypy src/likedbg
git add src/likedbg/cli.py tests/test_cli_foreign.py
git commit -m "feat(foreign): cmd_foreign + main dispatch on [foreign].image"
```

---

### Task 13: `Session.send_keys` + `console_upload` + `--upload`

**Files:**
- Modify: `src/likedbg/session.py`, `src/likedbg/foreign.py`, `src/likedbg/cli.py`, `tests/test_session.py`
- Test: `tests/test_session.py`, `tests/test_foreign.py`, `tests/test_cli_foreign.py`

**Interfaces:**
- Consumes: `Session._tmux`, `Session._runner`, `run_artifacts` console log path.
- Produces:
  - `Session.send_keys(pane: str, keys: str, *, enter: bool = True) -> None` — `tmux send-keys -t <pane> <keys>` (+ `Enter` when `enter`).
  - `foreign.console_upload(session, pane: str, file: Path, *, read_console: Callable[[], str]) -> None` — probe (`command -v base64` + writable `/tmp`), chunked base64 send, end-marker, verify byte-count + hash echoed on the console. Raises `ForeignError` "use repack" if the probe fails, or on a size/hash mismatch.
  - `cli.cmd_upload(workspace, *, run_id: str, file: str) -> int` and a `--upload` arg wired in `main`.

- [ ] **Step 1: Write the failing tests**

Update `tests/test_session.py::test_session_has_no_shell_driving_layout_helpers` to drop the `send_keys` assertion (keep `split`/`open_debug_layout`), and add:

```python
def test_send_keys_issues_tmux_send_keys_with_enter():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).send_keys("%2", "echo hi")
    assert rec.calls == [["tmux", "send-keys", "-t", "%2", "echo hi", "Enter"]]


def test_send_keys_without_enter_omits_enter():
    rec = Recorder()
    Session("LIKE-DBG", runner=rec).send_keys("%2", "partial", enter=False)
    assert rec.calls == [["tmux", "send-keys", "-t", "%2", "partial"]]
```

Add to `tests/test_foreign.py`:

```python
def test_console_upload_probe_failure_says_use_repack(tmp_path):
    from likedbg.foreign import console_upload

    payload = tmp_path / "expl"
    payload.write_bytes(b"\x7fELFsmall")

    class _Sess:
        def __init__(self):
            self.sent = []

        def send_keys(self, pane, keys, *, enter=True):
            self.sent.append(keys)

    sess = _Sess()
    # console read reports base64 missing -> probe fails
    with pytest.raises(ForeignError, match="use repack"):
        console_upload(sess, "%2", payload, read_console=lambda: "LIKEDBG-PROBE base64=no tmp=yes\n")


def test_console_upload_sends_chunks_and_verifies(tmp_path):
    from hashlib import sha256

    from likedbg.foreign import console_upload

    payload = tmp_path / "expl"
    data = b"\x7fELF" + b"A" * 40
    payload.write_bytes(data)
    digest = sha256(data).hexdigest()

    class _Sess:
        def __init__(self):
            self.sent = []

        def send_keys(self, pane, keys, *, enter=True):
            self.sent.append(keys)

    sess = _Sess()
    # probe OK, then the guest echoes matching size + sha256
    reads = iter(
        [
            "LIKEDBG-PROBE base64=yes tmp=yes\n",
            f"LIKEDBG-DONE size={len(data)} sha={digest}\n",
        ]
    )
    console_upload(sess, "%2", payload, read_console=lambda: next(reads))
    joined = "\n".join(sess.sent)
    assert "base64 -d" in joined  # decode step sent
    assert any("LIKEDBG-PROBE" in s for s in sess.sent)  # probe sent
```

(The exact protocol strings are an implementation choice — keep the test assertions and the implementation in sync; the point is: probe → chunked base64 → verify.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_session.py tests/test_foreign.py -k "send_keys or console_upload" -v`
Expected: FAIL (`Session` has no `send_keys`; `cannot import name 'console_upload'`).

- [ ] **Step 3: Implement**

In `src/likedbg/session.py`, add to `Session`:

```python
    def send_keys(self, pane: str, keys: str, *, enter: bool = True) -> None:
        args = ["send-keys", "-t", pane, keys]
        if enter:
            args.append("Enter")
        self._tmux(*args)
```

In `src/likedbg/foreign.py`, add (`import base64`, `from hashlib import sha256`, `from typing import Callable`):

```python
_PROBE = "LIKEDBG-PROBE"
_DONE = "LIKEDBG-DONE"


def console_upload(
    session: Any,
    pane: str,
    file: Path,
    *,
    read_console: Callable[[], str],
    chunk: int = 512,
    dest: str = "/tmp/exploit",
) -> None:
    """Best-effort live upload of a SMALL static exploit over the serial console (no reboot).

    Probes for base64 + a writable /tmp (else ForeignError 'use repack'), sends the payload as
    chunked base64 appended to `dest`, then verifies the echoed byte-count + sha256 match.
    Repack (ForeignRepackStage) is the reliable fallback.
    """
    session.send_keys(pane, f'echo "{_PROBE} base64=$(command -v base64 >/dev/null && echo yes || echo no) '
                             f'tmp=$(touch /tmp/.lk && echo yes || echo no)"')
    probe = read_console()
    if "base64=yes" not in probe or "tmp=yes" not in probe:
        raise ForeignError(
            "guest lacks base64 or a writable /tmp for console-upload",
            remedy="use repack (set [foreign].exploit and reboot)",
        )

    data = file.read_bytes()
    session.send_keys(pane, f": > {dest}.b64")
    b64 = base64.b64encode(data).decode()
    for i in range(0, len(b64), chunk):
        session.send_keys(pane, f"printf %s {b64[i : i + chunk]} >> {dest}.b64")
    session.send_keys(pane, f"base64 -d {dest}.b64 > {dest} && chmod +x {dest}")
    session.send_keys(
        pane,
        f'echo "{_DONE} size=$(wc -c < {dest}) sha=$(sha256sum {dest} | cut -d\' \' -f1)"',
    )

    echoed = read_console().replace("\r\n", "\n")
    want_size = str(len(data))
    want_sha = sha256(data).hexdigest()
    if f"size={want_size}" not in echoed or f"sha={want_sha}" not in echoed:
        raise ForeignError(
            "console-upload verification failed (size/hash mismatch)",
            remedy="chunking corrupted the transfer — retry or use repack",
        )
```

In `src/likedbg/cli.py`, add a `--upload` arg (near `--run`) `parser.add_argument("--upload", default="", metavar="EXPLOIT-PATH")`, dispatch it near the `--run` guard:

```python
        if args.upload:
            return cmd_upload(workspace, run_id=args.run_id, file=args.upload)
```

Implement `cmd_upload`: resolve the run dir + its `@likedbg_debuggee_pane` tmux option (the live serial pane), build a `Session`, read the console via `run_artifacts` `console_raw` tail, and call `console_upload`. (Reuse `_resolve_run` from the exploit/insmod path for the run dir; read the debuggee pane id from `session.get_option("@likedbg_debuggee_pane")`.) Keep it thin — the protocol lives in `foreign.console_upload`.

- [ ] **Step 4: Run to verify pass**

Run: `uv run pytest tests/test_session.py tests/test_foreign.py -q`
Expected: PASS.

- [ ] **Step 5: Lint + commit**

```bash
uv run ruff check src/likedbg && uv run mypy src/likedbg
git add src/likedbg/session.py src/likedbg/foreign.py src/likedbg/cli.py tests/test_session.py tests/test_foreign.py tests/test_cli_foreign.py
git commit -m "feat(foreign): Session.send_keys + console_upload (--upload) live delivery"
```

---

### Task 14: Docs — ADR-0010, CONTEXT.md, example scenario

**Files:**
- Create: `docs/adr/ADR-0010-foreign-kernel-adopt.md`, `configs/scenarios/example-foreign.toml.example` (or a documented commented scenario)
- Modify: `docs/CONTEXT.md` (glossary), `README`/roadmap if applicable
- Test: none (docs) — but run the full suite to confirm nothing regressed.

**Interfaces:** none (documentation).

- [ ] **Step 1: Write ADR-0010**

Create `docs/adr/ADR-0010-foreign-kernel-adopt.md` capturing the brainstorm decisions (match the existing ADR format in `docs/adr/`): `[foreign]` scenario config selects a Manifest-free adopt path; skip ProfileVerification; authoritative cmdline (no imposed mitigations, only `console=` + gdbstub added); arch auto-detect from the vmlinux ELF (override via `[foreign].arch`); vmlinux auto-extract from bzImage (x86) but stripped → no gdb function symbols (provide `[foreign].vmlinux` for symbols); exploit delivery = repack (reliable) + optional console-upload, always-manual run; repack/musl in a standalone `like_musl` container with cross-musl toolchains for both arches.

- [ ] **Step 2: Add CONTEXT.md glossary entries**

Add **Foreign kernel** and **Initramfs repack** definitions to `docs/CONTEXT.md` (follow the existing glossary style).

- [ ] **Step 3: Add an example scenario**

Create `configs/scenarios/example-foreign.toml.example`:

```toml
# Example CTF/foreign-kernel scenario. Copy to configs/scenarios/<name>.toml and run:
#   start_kgdb -c <name>
[foreign]
image = "ctf/lk01/bzImage"            # boot image (abs or workspace-relative); presence selects foreign
vmlinux = "ctf/lk01/vmlinux"          # optional; provides gdb symbols. Omit (x86) to auto-extract (stripped)
initramfs = "ctf/lk01/initramfs.cpio.gz"
cmdline = "console=ttyS0 kaslr quiet panic=-1"   # used VERBATIM; only console=/gdbstub added
# arch = "x86_64"                     # optional override; else auto-detected from the vmlinux ELF
# qemu_extra = ["-cpu", "qemu64,+smep,+smap"]     # mirror the challenge's extra QEMU flags
# exploit = "ctf/lk01/exploit.c"      # optional: repack-inject at /exploit (musl-static .c or prebuilt binary)
```

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run mypy src/likedbg`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add docs/adr/ADR-0010-foreign-kernel-adopt.md docs/CONTEXT.md configs/scenarios/example-foreign.toml.example
git commit -m "docs(foreign): ADR-0010 + CONTEXT glossary + example scenario"
```

---

### Task 15: Live gate — boot + debug + exploit, both arches (mac)

**Files:**
- Create: transcript under `docs/superpowers/notes/2026-07-07-foreign-kernel-live-gate.md`
- No production code (validation only). If a step reveals a bug, fix it in the owning task's module with a regression test first.

**Interfaces:** none — this is the spec §7 live gate. Requires Docker/colima + QEMU on the mac host and real CTF-style artifacts.

**Prerequisites (artifacts):** a small CTF-style target per arch: a boot image (`bzImage` x86_64 / `Image` arm64), a `vmlinux` with at least a symbol table, and a busybox `initramfs.cpio.gz`. Obtain by building a tiny kernel via the existing like-dbg pipeline (yields a real `vmlinux` + image) plus a busybox initramfs, or adopt a known public CTF challenge. Place under `ctf/<name>/` and write `configs/scenarios/<name>.toml`.

- [ ] **Step 1: Build the `like_musl` image**

Run: `./start_kgdb --build-images` (or a musl-only build). Confirm `like_musl:latest` exists and the cross toolchains resolve: `docker run --rm like_musl:latest x86_64-linux-musl-gcc --version && docker run --rm like_musl:latest aarch64-linux-musl-gcc --version`.
Expected: both compilers print a version. (If musl.cc is down, switch the dockerfile to the `musl-cross-make` fallback — see Risks — and rebuild.)

- [ ] **Step 2: x86_64 gate (in-container TCG on mac)**

In a tmux session: `./start_kgdb -c <x86-challenge>`. Confirm: (a) the debuggee pane reaches an interactive busybox shell; (b) the debugger pane's gdb attaches and resolves a known symbol — e.g. `break __x64_sys_open`, `continue`, trigger it, hit the breakpoint; (c) with `[foreign].exploit=<tiny>.c` set, the repacked initramfs contains `/exploit`; `continue`, then run `/exploit` manually from the console; (d) `./start_kgdb --upload ./expl` delivers a binary live and it runs. If the exploit panics, confirm `--analyze-crash latest` produces a crash report from `console.raw`.
Expected: all four succeed. Capture the transcript.

- [ ] **Step 3: arm64 gate (native-host hvf on mac)**

Repeat Step 2 with an arm64 `Image` + provided `vmlinux` + arm64 busybox initramfs and an `aarch64` exploit. Confirm boot + gdb symbol resolution + repack-inject + manual run.
Expected: success (or record any arm64-specific limitation).

- [ ] **Step 4: Verify cmdline fidelity + no imposed mitigations**

Inspect `artifacts/runs/latest/commands/` (the recorded QEMU argv): confirm `-append` is the challenge cmdline verbatim + `console=<dev>` only, with NO `nokaslr`/`nosmep`/`pti=on`/`oops=panic` tokens, and `qemu_extra` present on the argv.
Expected: matches the scenario's `cmdline` exactly.

- [ ] **Step 5: Record the transcript + commit**

Write `docs/superpowers/notes/2026-07-07-foreign-kernel-live-gate.md` (both arches, commands + observations + any deviations), then:

```bash
git add docs/superpowers/notes/2026-07-07-foreign-kernel-live-gate.md
git commit -m "docs(foreign): live-gate transcript (x86_64 + arm64 on mac)"
```

---

## Self-Review

**Spec coverage** (spec §→task):
- §2/§3.1 `[foreign]` config selects the path → Task 1, dispatch in Task 12.
- §3.3/§4.2 arch auto-detect (ELF), override → Task 2 (`detect_arch`), Task 5 (`resolve_foreign`).
- §2/§3.4/§4.2 vmlinux auto-extract → Task 3 (script+image), Task 4 (`extract_vmlinux`), Task 5 dispatch.
- §2/§3.5/§4.4 authoritative cmdline, console+gdbstub only, extra_boot_args, qemu_extra → Task 7.
- §4.1 `ForeignCfg` → Task 1.
- §3.7/§4.6 `like_musl` cross-musl image → Task 3.
- §2B/§4.2 repack + musl-compile/prebuilt inject → Task 6, Task 10 (stage).
- §4.3 `ForeignAdoptStage` (Manifest-free, record_kernel_paths config=None) → Task 9.
- §4.3 `ForeignRepackStage` → Task 10.
- §4.3 `build_foreign_pipeline` + dispatch → Task 11, Task 12.
- §4.5 gdb symbols via mount source + `/ksrc/vmlinux` → Task 9 (ctx.vmlinux) + Task 11 (gdb_mount_source).
- §2B/§4.2 console-upload (probe-gated, verified) + `Session.send_keys` → Task 13.
- §3.8 Manifest-free, skip ProfileVerification → Task 11 (pipeline omits it) + Task 12 (run_resolution not required by the foreign stages).
- §6 error handling → Tasks 4/5/6/12/13 (each raises `ForeignError` with a remedy); missing-guest-block refusal for `--run`/`--insmod`/`--rmmod` is already enforced by existing code (a foreign `run.json` has no `guest` block), so no new code — verify in the live gate.
- §7 unit tests → every task; live gate → Task 15.
- §8 docs → Task 14.
- §9 risks (musl.cc, cpio format, cmdline fidelity, arch mismatch, stripped vmlinux) → surfaced in Task 3 dockerfile comment + Task 15 gate steps + Risks below.

**Type consistency:** `ForeignKernel(image, vmlinux, initramfs, arch, cmdline)` is constructed identically in Tasks 5/9/10/11 tests. `resolve_foreign(container, cfg, workspace, *, out_dir, image)`, `repack_initramfs(container, *, initramfs, exploit, arch, out, image)`, `extract_vmlinux(container, image_path, out, *, image)` signatures are stable across their defining task and all call sites (Tasks 9-12). `build_qemu_argv(..., foreign_cmdline=None, qemu_extra=())` (Task 7) matches the `DebuggeeStage` call (Task 8) and `PipelineContext` fields (Task 8). `MUSL_IMAGE` constant (Task 3) is used in Tasks 11/12.

## Risks (carried from spec §9 — resolve in the live gate)

- **cross-musl toolchain source:** `.dockerfile_musl` pulls from musl.cc (occasional downtime → build-repro risk). Fallback: `musl-cross-make` (reproducible, ~10 min/arch). Pin the exact source; the live gate builds the image once and verifies both compilers.
- **cpio format variance** (`newc` vs others; gzip/raw/xz): the unpack step auto-detects gzip; repack always emits `newc`. Verify the repacked cpio boots on each arch (Task 15).
- **stripped extracted vmlinux:** a bzImage-carved vmlinux has no `.symtab` → gdb gets no function symbols and `break start_kernel` will not resolve. Provide `[foreign].vmlinux` for symbolized debugging; extraction is the boot-and-attach fallback (documented in ADR-0010).
- **cmdline fidelity / arch mismatch:** verified in Task 15 Steps 4 (verbatim `-append`) and 2/3 (arch auto-detect drives the correct emulator + `set architecture`).
- **console-upload reliability:** probe-gated + hash-verified; repack is the reliable fallback (Task 13).
- **musl-static vs a glibc initramfs:** a glibc busybox may need a glibc-static exploit — the `[foreign].exploit` prebuilt-binary path is the escape hatch (Task 6 copy branch).

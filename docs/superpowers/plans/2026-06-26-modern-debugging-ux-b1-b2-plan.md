# Modern Debugging UX B1+B2 (Debug Profiles & Run Artifacts) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add named TOML debug profiles with post-build `.config` verification (B1) and per-run artifacts with tmux pane-transcript capture (B2), replacing the INI config stack — without regressing today's default `uv run ./start_kgdb` behavior.

**Architecture:** Two new deep modules — `debug_profiles` (profile registry → resolved fragments/expectations/boot-args/effective runtime toggles) and `run_artifacts` (`RunRecorder` owning `artifacts/runs/<run-id>/`) — plus a rewritten `config` loader that emits whole-Settings provenance from a 6-layer TOML stack. Profile resolution is the build-time seam; run recording is the runtime seam. A new `ProfileVerificationStage` sits between `BuildStage` and `RootfsStage`, reading host-captured `.config`. Requested `Settings` stays frozen; effective runtime toggles are threaded as `ctx.effective_debuggee`.

**Tech Stack:** Python 3.12+, Pydantic v2, `tomllib` (stdlib), loguru, tmux, Docker (`ContainerService`), pytest, mypy, ruff, `uv`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-06-25-modern-debugging-ux-b1-b2-design.md`; §10 records the 12 grill decisions that AMEND the body — follow §10 where they conflict. ADR: `docs/adr/0006-toml-configuration-and-debug-profiles.md`.
- `dev` stays local — never `git push`. Do this work on a feature branch off `dev`.
- Scope is **B1 + B2 only.** No crash parsing (B3), GDB helper pack (B4), reset/snapshot (B5), or guest deploy / custom-module *building* (B6).
- TOML all the way: no INI fallback path may remain. `tomllib` is read-only — do not add a TOML *writer* dependency; generated config files are authored as static text.
- Deep modules: profile resolution and run recording each expose a small interface; `cli.py`/`qemu.py`/stages must not grow scattered profile/path special-cases.
- Portability: kconfig fragments, boot args, tmux pane piping, JSON/Markdown, Python only. No host-specific helper tools outside containers.
- `_Base` models are `frozen=True, extra="forbid"` (`config.py:29-33`) → list-typed fields are `tuple[...]`, and unknown keys are errors.
- Profile names match `[a-z0-9][a-z0-9._-]*`, lowercase, case-sensitive; filename must equal `name`; duplicate names are hard errors.
- Run-id format: `<YYYYMMDDTHHMMSSZ>-<build-label>` (UTC).
- All paths in this plan are repo-relative to `/Users/krah/Git/private/like-dbg`.
- After every task: `uv run pytest`, `uv run mypy src`, `uv run ruff check src` must pass before commit.

---

## File Structure

**New modules**
- `src/likedbg/input_hash.py` — shared content hashing (`hash_file`, `hash_tree`, `TreeHash`, `IgnoreRules`, `DEFAULT_IGNORE`).
- `src/likedbg/debug_profiles.py` — profile registry, `resolve_run`, `verify_config`, value objects (`RunResolution`, `ResolvedDebugProfiles`, `ConfigExpectation`, `ProfileVerification`), compatibility checks, `parse_profile_names`.
- `src/likedbg/run_artifacts.py` — `RunRecorder`, `RunStatus`.
- `src/likedbg/stages/profile_verification.py` — `ProfileVerificationStage` + the small `.config` reader helper.
- `configs/default.toml`, `configs/local.example.toml`, `configs/scenarios/.gitkeep`, `configs/profiles/*.toml`, `configs/fragments/profiles/*.config`.

**Modified modules**
- `src/likedbg/config.py` — TOML models (`SourceCfg`, `BuildCfg`, `DebuggingCfg`, `arch="native"`, `ext="pwndbg"` default) + `load_config` → `ConfigResolution(settings, provenance)`; drop `configparser`.
- `src/likedbg/host_profile.py` — `target_arch` field + `native` resolution.
- `src/likedbg/cache.py` — `build_recipe(arch=...)`, `BuildRecipe` patch hashes, `Manifest.kernel_release` + `config` path.
- `src/likedbg/stages/build.py` — apply patches; capture `.config` + `kernel_release` to host/manifest; record command.
- `src/likedbg/stages/download.py` — `resolve_version(SourceCfg)`, read `ctx.settings.source`.
- `src/likedbg/qemu.py` — `build_qemu_argv(effective_debuggee, host, *, target_arch, kernel_image, rootfs, extra_boot_args)`.
- `src/likedbg/stages/debuggee.py`, `src/likedbg/stages/debugger.py` — read `ctx.effective_debuggee`/`host.target_arch`; record commands via optional `RunRecorder`.
- `src/likedbg/session.py` — `pipe_pane`.
- `src/likedbg/pipeline.py` — `PipelineContext` gains `run_resolution`, `effective_debuggee`, `extra_boot_args`, `recorder`.
- `src/likedbg/logsetup.py` — `add_run_logfile(workspace, *, path=None)`.
- `src/likedbg/cli.py` — reordered flow, `--profile`/`--explain-config`, recorder wiring, transcript piping, restart re-pipe, TOML config paths.
- `docs/adr/0006-*.md`, `CONTEXT.md`, `docs/superpowers/ROADMAP.md`, `README.md`.
- `.gitignore` — add `configs/local.toml`.

**Removed**
- `configs/system.ini`, `configs/user.ini`, the `_FRAGMENTS` tuple, `KernelDlCfg`, `KernelBuilderCfg.mode/extra_args/patch_dir(singular)`, `load_settings`, all `configparser` use.

---

# Phase 1 — Foundations

## Task 1: `input_hash` module

**Files:**
- Create: `src/likedbg/input_hash.py`
- Test: `src/tests/test_input_hash.py`

**Interfaces:**
- Produces: `hash_file(path: Path) -> str`; `hash_tree(root: Path, *, ignore: IgnoreRules = DEFAULT_IGNORE) -> TreeHash`; `TreeHash(aggregate: str, files: tuple[tuple[str, str], ...])`; `IgnoreRules`; `DEFAULT_IGNORE`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_input_hash.py
from pathlib import Path

from likedbg.input_hash import DEFAULT_IGNORE, hash_file, hash_tree


def test_hash_file_is_sha256_of_content(tmp_path: Path) -> None:
    f = tmp_path / "a.txt"
    f.write_bytes(b"hello")
    # sha256("hello")
    assert hash_file(f) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_hash_tree_is_order_independent_and_content_sensitive(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.c").write_text("b")
    (tmp_path / "a.c").write_text("a")
    first = hash_tree(tmp_path)
    # Rewriting identical content yields the same aggregate.
    (tmp_path / "a.c").write_text("a")
    assert hash_tree(tmp_path).aggregate == first.aggregate
    # Records are sorted by relative path.
    assert [rel for rel, _ in first.files] == ["a.c", "sub/b.c"]
    # A content change moves the aggregate.
    (tmp_path / "a.c").write_text("A")
    assert hash_tree(tmp_path).aggregate != first.aggregate


def test_hash_tree_ignores_build_junk(tmp_path: Path) -> None:
    (tmp_path / "keep.c").write_text("x")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    (tmp_path / "m.o").write_text("obj")
    (tmp_path / ".DS_Store").write_text("junk")
    th = hash_tree(tmp_path, ignore=DEFAULT_IGNORE)
    assert [rel for rel, _ in th.files] == ["keep.c"]


def test_hash_tree_empty_dir_is_stable(tmp_path: Path) -> None:
    assert hash_tree(tmp_path).aggregate == hash_tree(tmp_path).aggregate
    assert hash_tree(tmp_path).files == ()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_input_hash.py -v`
Expected: FAIL with `ModuleNotFoundError: likedbg.input_hash`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/likedbg/input_hash.py
"""Shared, deterministic content hashing for workspace inputs (patch dirs today;
exploit payloads / custom modules later). One aggregate SHA-256 over sorted
(relative-path, file-hash) records, with a small documented junk ignore list."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

_IGNORE_DIRS = frozenset({".git", "__pycache__", ".tmp_versions"})
_IGNORE_NAMES = frozenset({".DS_Store", "Module.symvers", "modules.order"})
_IGNORE_SUFFIXES = frozenset({".o", ".ko", ".mod", ".mod.c"})


@dataclass(frozen=True)
class IgnoreRules:
    dirs: frozenset[str] = _IGNORE_DIRS
    names: frozenset[str] = _IGNORE_NAMES
    suffixes: frozenset[str] = _IGNORE_SUFFIXES

    def skip_dir(self, name: str) -> bool:
        return name in self.dirs

    def skip_file(self, name: str) -> bool:
        return name in self.names or any(name.endswith(s) for s in self.suffixes)


DEFAULT_IGNORE = IgnoreRules()


@dataclass(frozen=True)
class TreeHash:
    aggregate: str
    files: tuple[tuple[str, str], ...]  # (relative POSIX path, sha256), sorted by path


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_tree(root: Path, *, ignore: IgnoreRules = DEFAULT_IGNORE) -> TreeHash:
    records: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(ignore.skip_dir(part) for part in rel_parts[:-1]):
            continue
        if ignore.skip_file(path.name):
            continue
        rel = "/".join(rel_parts)
        records.append((rel, hash_file(path)))
    records.sort()
    agg = hashlib.sha256()
    for rel, digest in records:
        agg.update(rel.encode())
        agg.update(b"\0")
        agg.update(digest.encode())
        agg.update(b"\n")
    return TreeHash(aggregate=agg.hexdigest(), files=tuple(records))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_input_hash.py -v && uv run mypy src/likedbg/input_hash.py && uv run ruff check src/likedbg/input_hash.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/input_hash.py src/tests/test_input_hash.py
git commit -m "feat(input_hash): deterministic content hashing for workspace inputs"
```

---

## Task 2: TOML config models

**Files:**
- Modify: `src/likedbg/config.py` (models section, lines 20-89)
- Test: `src/tests/test_config_models.py` (new)

**Interfaces:**
- Produces: `GeneralCfg(arch: Literal["native","x86_64","arm64"]="native", workspace_dir, mac_storage)`; `SourceCfg(kind: Literal["mmp","tag","commit"]="mmp", value: str="")`; `BuildCfg(compiler, toolchain, rust, label_suffix, patch_dirs: tuple[str,...], custom_modules: tuple[str,...], extra_fragments: tuple[str,...])`; `DebuggeeCfg` (unchanged fields, drop `kvm`); `DebuggerCfg(ext="pwndbg")`; `DebuggingCfg(profiles: tuple[str,...]=("exploit-dev",))`; `Settings(general, source, build, rootfs, debuggee, debugger, debugging)`.
- Consumes: nothing yet (loader is Task 3).

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_config_models.py
import pytest
from pydantic import ValidationError

from likedbg.config import BuildCfg, DebuggerCfg, DebuggingCfg, GeneralCfg, Settings, SourceCfg


def test_defaults_match_grill_decisions() -> None:
    s = Settings()
    assert s.general.arch == "native"
    assert s.source.kind == "mmp"
    assert s.debugger.ext == "pwndbg"  # de facto default (Q9)
    assert s.debugging.profiles == ("exploit-dev",)


def test_list_fields_are_tuples() -> None:
    b = BuildCfg(patch_dirs=["patches/uaf"], extra_fragments=["configs/fragments/local/x.config"])
    assert b.patch_dirs == ("patches/uaf",)
    assert b.extra_fragments == ("configs/fragments/local/x.config",)
    assert DebuggingCfg(profiles=["kasan", "lockdep"]).profiles == ("kasan", "lockdep")


def test_unknown_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GeneralCfg(arch="native", bogus=1)  # type: ignore[call-arg]


def test_source_kind_constrained() -> None:
    with pytest.raises(ValidationError):
        SourceCfg(kind="branch", value="x")  # type: ignore[arg-type]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_config_models.py -v`
Expected: FAIL (`ImportError: cannot import name 'SourceCfg'`).

- [ ] **Step 3: Write minimal implementation**

Replace `config.py` lines 20-89 (the type aliases + model classes; keep `_Base`) with:

```python
Arch = Literal["x86_64", "arm64"]
RequestedArch = Literal["native", "x86_64", "arm64"]
Accel = Literal["auto", "kvm", "hvf", "tcg"]
MacStorage = Literal["auto", "bind", "volume"]
SourceKind = Literal["mmp", "tag", "commit"]
Compiler = Literal["clang", "gcc"]
Ext = Literal["gef", "pwndbg"]
Network = Literal["auto", "host", "published"]


class GeneralCfg(_Base):
    arch: RequestedArch = "native"
    workspace_dir: str | None = None
    mac_storage: MacStorage = "auto"


class SourceCfg(_Base):
    kind: SourceKind = "mmp"
    value: str = ""


class BuildCfg(_Base):
    compiler: Compiler = "clang"
    toolchain: str = "auto"
    rust: bool = False
    label_suffix: str = ""
    patch_dirs: tuple[str, ...] = ()
    custom_modules: tuple[str, ...] = ()  # B1: validated schema slot only; built in B6.
    extra_fragments: tuple[str, ...] = ()


class RootfsCfg(_Base):
    distribution: str = "bookworm"
    hostname: str = "LIKE-DBG"


class DebuggeeCfg(_Base):
    memory_mib: int = 1024
    smp: int = 1
    accel: Accel = "auto"
    network: Network = "auto"
    gdb: bool = True
    gdb_port: int = 1234
    kaslr: bool = False
    smep: bool = True
    smap: bool = True
    kpti: bool = True
    panic: str = "halt"


class DebuggerCfg(_Base):
    ext: Ext = "pwndbg"


class DebuggingCfg(_Base):
    profiles: tuple[str, ...] = ("exploit-dev",)


class Settings(_Base):
    general: GeneralCfg = GeneralCfg()
    source: SourceCfg = SourceCfg()
    build: BuildCfg = BuildCfg()
    rootfs: RootfsCfg = RootfsCfg()
    debuggee: DebuggeeCfg = DebuggeeCfg()
    debugger: DebuggerCfg = DebuggerCfg()
    debugging: DebuggingCfg = DebuggingCfg()
```

(Leave the old `load_settings`/`_layer`/`_read` in place for now; Task 3 replaces them. The legacy stages still import `KernelDlCfg` — temporarily keep `class KernelDlCfg(_Base)` so the tree imports until Task 3/Task 14 remove it.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_config_models.py -v`
Expected: PASS. (`uv run pytest` as a whole will have failures in INI-based tests — expected until Phase 9; keep going.)

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/config.py src/tests/test_config_models.py
git commit -m "feat(config): TOML Settings models (native arch, source kind/value, tuple lists, pwndbg default)"
```

---

## Task 3: TOML provenance loader

**Files:**
- Modify: `src/likedbg/config.py` (replace `_layer`/`_read`/`load_settings` with TOML loader; remove `configparser` + `cast`)
- Test: `src/tests/test_config_loader.py` (new)

**Interfaces:**
- Produces:
  - `def load_config(workspace: Path, *, scenario: Path | None = None, cli_overrides: dict[str, dict[str, str]] | None = None) -> ConfigResolution`
  - `class ConfigResolution` with `settings: Settings`, `provenance: dict[tuple[str, str], str]`, and `def effective_debuggee(self, profile_defaults: dict[str, str]) -> tuple[DebuggeeCfg, dict[tuple[str, str], str]]`
  - Layer name constants: `LAYER_BUILTIN="built-in"`, `LAYER_DEFAULT="default"`, `LAYER_PROFILE="profile"`, `LAYER_LOCAL="local"`, `LAYER_SCENARIO="scenario"`, `LAYER_CLI="cli"`
- Consumes: models from Task 2.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_config_loader.py
from pathlib import Path

import pytest

from likedbg.config import LAYER_DEFAULT, LAYER_LOCAL, LAYER_PROFILE, load_config
from likedbg.errors import ConfigError


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_default_only(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[source]\nkind = "mmp"\nvalue = "6.6.30"\n')
    cr = load_config(tmp_path)
    assert cr.settings.source.value == "6.6.30"
    assert cr.provenance[("source", "value")] == LAYER_DEFAULT


def test_local_overrides_default_with_provenance(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[debugger]\next = "pwndbg"\n')
    _write(tmp_path / "configs" / "local.toml", '[debugger]\next = "gef"\n')
    cr = load_config(tmp_path)
    assert cr.settings.debugger.ext == "gef"
    assert cr.provenance[("debugger", "ext")] == LAYER_LOCAL


def test_missing_default_is_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path)


def test_effective_debuggee_injects_profile_layer4(tmp_path: Path) -> None:
    # default.toml has kaslr off; a profile default flips it on; no user override → profile wins.
    _write(tmp_path / "configs" / "default.toml", "[debuggee]\nkaslr = false\n")
    cr = load_config(tmp_path)
    eff, prov = cr.effective_debuggee({"kaslr": "true"})
    assert eff.kaslr is True
    assert prov[("debuggee", "kaslr")] == LAYER_PROFILE


def test_effective_debuggee_user_beats_profile(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", "[debuggee]\nkaslr = false\n")
    _write(tmp_path / "configs" / "local.toml", "[debuggee]\nkaslr = false\n")
    cr = load_config(tmp_path)
    eff, prov = cr.effective_debuggee({"kaslr": "true"})
    assert eff.kaslr is False
    assert prov[("debuggee", "kaslr")] == LAYER_LOCAL


def test_cli_override_and_scenario(tmp_path: Path) -> None:
    _write(tmp_path / "configs" / "default.toml", '[general]\narch = "native"\n')
    _write(tmp_path / "configs" / "scenarios" / "lk01.toml", '[general]\narch = "x86_64"\n')
    cr = load_config(
        tmp_path,
        scenario=tmp_path / "configs" / "scenarios" / "lk01.toml",
        cli_overrides={"debugger": {"ext": "gef"}},
    )
    assert cr.settings.general.arch == "x86_64"
    assert cr.settings.debugger.ext == "gef"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_config_loader.py -v`
Expected: FAIL (`ImportError: cannot import name 'load_config'`).

- [ ] **Step 3: Write minimal implementation**

Update the `config.py` header imports: drop `import configparser` and `from typing import cast`; add `import tomllib` and `from dataclasses import dataclass`. Replace `_layer`/`_read`/`load_settings` (lines 92-141) with:

```python
LAYER_BUILTIN = "built-in"
LAYER_DEFAULT = "default"
LAYER_PROFILE = "profile"
LAYER_LOCAL = "local"
LAYER_SCENARIO = "scenario"
LAYER_CLI = "cli"

_SECTION_MODELS: dict[str, type[_Base]] = {
    "general": GeneralCfg,
    "source": SourceCfg,
    "build": BuildCfg,
    "rootfs": RootfsCfg,
    "debuggee": DebuggeeCfg,
    "debugger": DebuggerCfg,
    "debugging": DebuggingCfg,
}

# Section→key→value layer dict.
_Layer = dict[str, dict[str, object]]


def _read_toml(path: Path) -> _Layer:
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    # tomllib gives nested dicts already keyed by section.
    return {sec: dict(kv) for sec, kv in data.items() if isinstance(kv, dict)}


def _merge(layers: list[tuple[str, _Layer]]) -> tuple[dict[str, dict[str, object]], dict[tuple[str, str], str]]:
    """Apply ordered (low→high) layers; return merged section dicts + winning-layer provenance."""
    merged: dict[str, dict[str, object]] = {}
    prov: dict[tuple[str, str], str] = {}
    for name, layer in layers:
        for section, kv in layer.items():
            for key, val in kv.items():
                merged.setdefault(section, {})[key] = val
                prov[(section, key)] = name
    return merged, prov


def _build_settings(merged: dict[str, dict[str, object]]) -> Settings:
    kwargs: dict[str, _Base] = {}
    for section, model in _SECTION_MODELS.items():
        try:
            kwargs[section] = model(**merged.get(section, {}))
        except ValidationError as exc:
            raise ConfigError(
                f"invalid [{section}] configuration: {exc.errors()[0]['msg']}",
                remedy=f"check the [{section}] section of your TOML config",
            ) from exc
    return Settings(**kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True)
class ConfigResolution:
    settings: Settings
    provenance: dict[tuple[str, str], str]
    _ordered_layers: tuple[tuple[str, _Layer], ...]  # built-in placeholder excluded; low→high

    def effective_debuggee(self, profile_defaults: dict[str, str]) -> tuple[DebuggeeCfg, dict[tuple[str, str], str]]:
        """Re-merge [debuggee] with profile defaults spliced in at layer 4 (above default, below local)."""
        rebuilt: list[tuple[str, _Layer]] = []
        for name, layer in self._ordered_layers:
            rebuilt.append((name, layer))
            if name == LAYER_DEFAULT and profile_defaults:
                rebuilt.append((LAYER_PROFILE, {"debuggee": dict(profile_defaults)}))
        if profile_defaults and not any(n == LAYER_DEFAULT for n, _ in self._ordered_layers):
            rebuilt.insert(0, (LAYER_PROFILE, {"debuggee": dict(profile_defaults)}))
        merged, prov = _merge(rebuilt)
        return _build_settings(merged).debuggee, prov


def load_config(
    workspace: Path,
    *,
    scenario: Path | None = None,
    cli_overrides: dict[str, dict[str, str]] | None = None,
) -> ConfigResolution:
    default_path = workspace / "configs" / "default.toml"
    if not default_path.exists():
        raise ConfigError(
            f"project config not found: {default_path}",
            remedy="create configs/default.toml (see configs/local.example.toml)",
        )
    layers: list[tuple[str, _Layer]] = [(LAYER_DEFAULT, _read_toml(default_path))]
    local_path = workspace / "configs" / "local.toml"
    if local_path.exists():
        layers.append((LAYER_LOCAL, _read_toml(local_path)))
    if scenario is not None:
        if not scenario.exists():
            raise ConfigError(f"scenario config not found: {scenario}", remedy="check the -c name/path")
        layers.append((LAYER_SCENARIO, _read_toml(scenario)))
    if cli_overrides:
        layers.append((LAYER_CLI, {sec: dict(kv) for sec, kv in cli_overrides.items()}))
    merged, prov = _merge(layers)
    return ConfigResolution(settings=_build_settings(merged), provenance=prov, _ordered_layers=tuple(layers))
```

Note: keys not set by any layer are absent from `provenance`; callers treat "absent" as `LAYER_BUILTIN`. Keep `from pydantic import ValidationError` import.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_config_loader.py -v && uv run mypy src/likedbg/config.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/config.py src/tests/test_config_loader.py
git commit -m "feat(config): 6-layer TOML loader with whole-Settings provenance + effective_debuggee splice"
```

---

## Task 4: `HostProfile.target_arch` + `native` resolution

**Files:**
- Modify: `src/likedbg/host_profile.py` (lines 77-119)
- Test: `src/tests/test_host_profile.py` (extend; create if absent)

**Interfaces:**
- Produces: `HostProfile.target_arch: Arch` (concrete `x86_64`/`arm64`).
- Consumes: `Settings.general.arch` (may be `"native"`).

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_host_profile.py  (add these; reuse existing Probes-stubbing pattern if present)
from pathlib import Path

from likedbg.config import Settings, GeneralCfg
from likedbg.host_profile import HostProfile, Probes


def _probes(*, system: str, machine: str) -> Probes:
    return Probes(
        system=lambda: system,
        machine=lambda: machine,
        kvm_accessible=lambda: False,
        hvf_supported=lambda: True,
        native_qemu_present=lambda _a: True,
        workspace_case_sensitive=lambda _p: True,
    )


def test_native_resolves_to_host_arch(tmp_path: Path) -> None:
    s = Settings(general=GeneralCfg(arch="native"))
    hp = HostProfile.detect(s, tmp_path, _probes(system="darwin", machine="arm64"))
    assert hp.target_arch == "arm64"
    assert hp.accel == "hvf" and hp.debuggee_mode == "native-host"  # same-arch path uses target_arch


def test_explicit_cross_arch_kept(tmp_path: Path) -> None:
    s = Settings(general=GeneralCfg(arch="x86_64"))
    hp = HostProfile.detect(s, tmp_path, _probes(system="darwin", machine="arm64"))
    assert hp.target_arch == "x86_64"
    assert hp.debuggee_mode == "in-container"  # cross-arch on mac → TCG in container
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_host_profile.py -v`
Expected: FAIL (`AttributeError: ... 'target_arch'`).

- [ ] **Step 3: Write minimal implementation**

In `host_profile.py`, add `target_arch: Arch` to the dataclass (after `host_arch`), and in `detect` replace the `guest_arch`/`same_arch` lines:

```python
        os_name = probes.system()
        host_arch = probes.machine()
        requested = settings.general.arch
        target_arch: Arch = host_arch if requested == "native" else requested  # type: ignore[assignment]
        same_arch = target_arch == host_arch

        capable_native_hvf = (
            os_name == "darwin" and same_arch and probes.hvf_supported() and probes.native_qemu_present(target_arch)
        )
        capable_kvm = os_name == "linux" and same_arch and probes.kvm_accessible()
        requested_accel = settings.debuggee.accel
        accel, mode = cls._resolve_accel(requested_accel, capable_native_hvf, capable_kvm, os_name)
        storage = cls._resolve_storage(settings, os_name, workspace, probes)
        network_mode = cls._resolve_network(settings.debuggee.network, os_name)
        addr = "localhost" if network_mode == "host" else "host.docker.internal"
        return cls(
            os=os_name,
            host_arch=host_arch,
            target_arch=target_arch,
            accel=accel,
            debuggee_mode=mode,
            storage_mode=storage,
            gdbstub_addr=addr,
            ssh_addr=addr,
            network_mode=network_mode,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_host_profile.py -v && uv run mypy src/likedbg/host_profile.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/host_profile.py src/tests/test_host_profile.py
git commit -m "feat(host_profile): resolve native to target_arch inside detect"
```

---

# Phase 2 — Debug Profiles

## Task 5: Profile definition schema + registry loading

**Files:**
- Create: `src/likedbg/debug_profiles.py` (schema + registry only this task)
- Test: `src/tests/test_debug_profiles_registry.py`

**Interfaces:**
- Produces: Pydantic `ProfileDef(name, kind, description, implies, fragments, boot_arg, runtime_defaults, warning, expect)`; `ConfigExpectation` (alias of an `Expect` model); `load_profiles(workspace: Path) -> dict[str, ProfileDef]`; `parse_profile_names(raw: str | Sequence[str]) -> tuple[str, ...]`.
- Constraints: filename == name; unique names; name regex `^[a-z0-9][a-z0-9._-]*$`; unknown fields error; `kind ∈ {base, addon}`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_debug_profiles_registry.py
from pathlib import Path

import pytest

from likedbg.debug_profiles import load_profiles, parse_profile_names
from likedbg.errors import ConfigError


def _profile(dirp: Path, name: str, body: str) -> None:
    dirp.mkdir(parents=True, exist_ok=True)
    (dirp / f"{name}.toml").write_text(body)


def test_load_minimal_addon(tmp_path: Path) -> None:
    pdir = tmp_path / "configs" / "profiles"
    _profile(pdir, "kasan", 'name = "kasan"\nkind = "addon"\ndescription = "x"\nimplies = ["crash-debug"]\n'
             'fragments = ["configs/fragments/profiles/kasan.config"]\n'
             '[[expect]]\nsymbol = "CONFIG_KASAN"\nvalue = "y"\nseverity = "hard"\n')
    reg = load_profiles(tmp_path)
    assert reg["kasan"].kind == "addon"
    assert reg["kasan"].implies == ("crash-debug",)
    assert reg["kasan"].expect[0].symbol == "CONFIG_KASAN"


def test_filename_must_match_name(tmp_path: Path) -> None:
    _profile(tmp_path / "configs" / "profiles", "kasan", 'name = "ubsan"\nkind = "addon"\ndescription = "x"\n')
    with pytest.raises(ConfigError):
        load_profiles(tmp_path)


def test_unknown_field_rejected(tmp_path: Path) -> None:
    _profile(tmp_path / "configs" / "profiles", "x", 'name = "x"\nkind = "addon"\ndescription = "d"\nbogus = 1\n')
    with pytest.raises(ConfigError):
        load_profiles(tmp_path)


def test_parse_profile_names() -> None:
    assert parse_profile_names("kasan,lockdep") == ("kasan", "lockdep")
    assert parse_profile_names(["exploit-dev"]) == ("exploit-dev",)
    with pytest.raises(ConfigError):
        parse_profile_names("")
    with pytest.raises(ConfigError):
        parse_profile_names("KASAN")  # uppercase rejected, not normalized
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_debug_profiles_registry.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Write minimal implementation**

```python
# src/likedbg/debug_profiles.py
"""Deep module for Debug profiles: loads declarative TOML, resolves the active set into
ordered fragments / expectations / boot args / effective runtime toggles, and verifies the
built .config. TOML defines facts; Python owns compatibility logic."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from likedbg.errors import ConfigError

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class _PBase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Expect(_PBase):
    symbol: str
    value: Literal["y", "m", "n"]  # "n" → "# CONFIG_FOO is not set"
    severity: Literal["hard", "soft"]
    arch: tuple[str, ...] | None = None
    kernel_min: str | None = None
    kernel_max: str | None = None


ConfigExpectation = Expect


class BootArg(_PBase):
    value: str
    arch: tuple[str, ...] | None = None
    kernel_min: str | None = None
    kernel_max: str | None = None
    profiles: tuple[str, ...] | None = None


class Warning_(_PBase):
    message: str
    arch: tuple[str, ...] | None = None
    accel: tuple[str, ...] | None = None
    host_os: tuple[str, ...] | None = None
    profiles: tuple[str, ...] | None = None


class _RuntimeDefaults(_PBase):
    debuggee: dict[str, object] = {}


class ProfileDef(_PBase):
    name: str
    kind: Literal["base", "addon"]
    description: str
    implies: tuple[str, ...] = ()
    fragments: tuple[str, ...] = ()
    boot_arg: tuple[BootArg, ...] = ()
    runtime_defaults: _RuntimeDefaults = _RuntimeDefaults()
    warning: tuple[Warning_, ...] = ()
    expect: tuple[Expect, ...] = ()


def parse_profile_names(raw: str | Sequence[str]) -> tuple[str, ...]:
    names = [p.strip() for p in raw.split(",")] if isinstance(raw, str) else [str(p).strip() for p in raw]
    names = [n for n in names if n]
    if not names:
        raise ConfigError("no debug profile specified", remedy="pass at least one profile name")
    for n in names:
        if not _NAME_RE.match(n):
            raise ConfigError(
                f"invalid debug profile name {n!r}",
                remedy="profile names are lowercase and match [a-z0-9][a-z0-9._-]*",
            )
    # de-duplicate, preserve first-seen order
    seen: dict[str, None] = {}
    for n in names:
        seen.setdefault(n, None)
    return tuple(seen)


def load_profiles(workspace: Path) -> dict[str, ProfileDef]:
    pdir = workspace / "configs" / "profiles"
    registry: dict[str, ProfileDef] = {}
    for path in sorted(pdir.glob("*.toml")):
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        try:
            pdef = ProfileDef(**data)
        except ValidationError as exc:
            raise ConfigError(
                f"invalid profile {path.name}: {exc.errors()[0]['msg']}",
                remedy=f"fix {path}",
            ) from exc
        if pdef.name != path.stem:
            raise ConfigError(
                f"profile filename/name mismatch: {path.name} declares name={pdef.name!r}",
                remedy=f"rename the file or the name field so they match",
            )
        if pdef.name in registry:
            raise ConfigError(f"duplicate profile name {pdef.name!r}", remedy=f"remove the duplicate under {pdir}")
        registry[pdef.name] = pdef
    return registry
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_debug_profiles_registry.py -v && uv run mypy src/likedbg/debug_profiles.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/debug_profiles.py src/tests/test_debug_profiles_registry.py
git commit -m "feat(debug_profiles): profile schema + registry loading + parse_profile_names"
```

---

## Task 6: `verify_config` + `ProfileVerification`

**Files:**
- Modify: `src/likedbg/debug_profiles.py` (add `verify_config`, `ProfileVerification`, `ResolvedDebugProfiles`, version helpers)
- Test: `src/tests/test_debug_profiles_verify.py`

**Interfaces:**
- Produces: `ResolvedDebugProfiles(names, base, expected_config, future_breakpoint_groups)`; `ProfileVerification(satisfied, missing_hard, missing_soft, warnings)`; `verify_config(config_text: str, resolved: ResolvedDebugProfiles, *, target_arch: str, kernel_release: str | None) -> ProfileVerification`; `parse_kernel_release(makefile_text: str) -> str`; `version_tuple(release: str) -> tuple[int, ...]`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_debug_profiles_verify.py
from likedbg.debug_profiles import (
    Expect, ResolvedDebugProfiles, parse_kernel_release, verify_config, version_tuple,
)


def _resolved(*exp: Expect) -> ResolvedDebugProfiles:
    return ResolvedDebugProfiles(names=("kasan",), base="exploit-dev", expected_config=exp, future_breakpoint_groups=())


def test_hard_pass_and_not_set_parsing() -> None:
    cfg = "CONFIG_KASAN=y\n# CONFIG_RANDOMIZE_BASE is not set\n"
    res = _resolved(
        Expect(symbol="CONFIG_KASAN", value="y", severity="hard"),
        Expect(symbol="CONFIG_RANDOMIZE_BASE", value="n", severity="hard"),
    )
    v = verify_config(cfg, res, target_arch="x86_64", kernel_release="6.6.30")
    assert not v.missing_hard and len(v.satisfied) == 2


def test_hard_fail() -> None:
    res = _resolved(Expect(symbol="CONFIG_KASAN", value="y", severity="hard"))
    v = verify_config("# CONFIG_KASAN is not set\n", res, target_arch="x86_64", kernel_release="6.6.30")
    assert [e.symbol for e in v.missing_hard] == ["CONFIG_KASAN"]


def test_soft_warns_not_fails() -> None:
    res = _resolved(Expect(symbol="CONFIG_FRAME_POINTER", value="y", severity="soft"))
    v = verify_config("", res, target_arch="x86_64", kernel_release="6.6.30")
    assert not v.missing_hard and [e.symbol for e in v.missing_soft] == ["CONFIG_FRAME_POINTER"]


def test_arch_selector_skips() -> None:
    res = _resolved(Expect(symbol="CONFIG_X", value="y", severity="hard", arch=("arm64",)))
    v = verify_config("", res, target_arch="x86_64", kernel_release="6.6.30")
    assert not v.missing_hard and not v.satisfied  # skipped entirely


def test_kernel_min_skips_on_older() -> None:
    res = _resolved(Expect(symbol="CONFIG_X", value="y", severity="hard", kernel_min="6.7"))
    v = verify_config("", res, target_arch="x86_64", kernel_release="6.6.30")
    assert not v.missing_hard


def test_parse_kernel_release() -> None:
    mk = "VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 30\nEXTRAVERSION =\nNAME = x\n"
    assert parse_kernel_release(mk) == "6.6.30"
    assert version_tuple("6.6.30") == (6, 6, 30)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_debug_profiles_verify.py -v`
Expected: FAIL (`ImportError`).

- [ ] **Step 3: Write minimal implementation**

Append to `debug_profiles.py`:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class ResolvedDebugProfiles:
    names: tuple[str, ...]
    base: str
    expected_config: tuple[Expect, ...]
    future_breakpoint_groups: tuple[str, ...]


@dataclass(frozen=True)
class ProfileVerification:
    satisfied: tuple[Expect, ...]
    missing_hard: tuple[Expect, ...]
    missing_soft: tuple[Expect, ...]
    warnings: tuple[str, ...]


def version_tuple(release: str) -> tuple[int, ...]:
    nums: list[int] = []
    for part in release.split("."):
        m = re.match(r"\d+", part)
        if not m:
            break
        nums.append(int(m.group()))
    return tuple(nums)


def parse_kernel_release(makefile_text: str) -> str:
    fields = {"VERSION": "", "PATCHLEVEL": "", "SUBLEVEL": "", "EXTRAVERSION": ""}
    for line in makefile_text.splitlines():
        for key in fields:
            m = re.match(rf"^{key}\s*=\s*(.*)$", line.strip())
            if m:
                fields[key] = m.group(1).strip()
    base = ".".join(v for v in (fields["VERSION"], fields["PATCHLEVEL"], fields["SUBLEVEL"]) if v)
    return base + fields["EXTRAVERSION"]


def _config_has(config_text: str, symbol: str, value: str) -> bool:
    if value == "n":
        return f"# {symbol} is not set" in config_text or not re.search(rf"^{re.escape(symbol)}=", config_text, re.M)
    return bool(re.search(rf"^{re.escape(symbol)}={value}$", config_text, re.M))


def _expect_applies(e: Expect, *, target_arch: str, kernel_release: str | None) -> bool:
    if e.arch is not None and target_arch not in e.arch:
        return False
    if kernel_release is not None:
        kv = version_tuple(kernel_release)
        if e.kernel_min is not None and kv < version_tuple(e.kernel_min):
            return False
        if e.kernel_max is not None and kv > version_tuple(e.kernel_max):
            return False
    return True


def verify_config(
    config_text: str, resolved: ResolvedDebugProfiles, *, target_arch: str, kernel_release: str | None
) -> ProfileVerification:
    satisfied: list[Expect] = []
    missing_hard: list[Expect] = []
    missing_soft: list[Expect] = []
    warnings: list[str] = []
    for e in resolved.expected_config:
        if not _expect_applies(e, target_arch=target_arch, kernel_release=kernel_release):
            continue
        if _config_has(config_text, e.symbol, e.value):
            satisfied.append(e)
        elif e.severity == "hard":
            missing_hard.append(e)
        else:
            missing_soft.append(e)
            warnings.append(f"soft expectation unmet: {e.symbol} expected {e.value}")
    return ProfileVerification(
        satisfied=tuple(satisfied),
        missing_hard=tuple(missing_hard),
        missing_soft=tuple(missing_soft),
        warnings=tuple(warnings),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_debug_profiles_verify.py -v && uv run mypy src/likedbg/debug_profiles.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/debug_profiles.py src/tests/test_debug_profiles_verify.py
git commit -m "feat(debug_profiles): verify_config with arch/kernel-version selectors + release parsing"
```

---

## Task 7: `resolve_run` (resolution, ordering, compatibility, effective toggles)

**Files:**
- Modify: `src/likedbg/debug_profiles.py` (add `RunResolution`, `resolve_run`, internal compat checks)
- Test: `src/tests/test_debug_profiles_resolve.py`

**Interfaces:**
- Produces:
  - `class RunResolution` (frozen): `requested_settings: Settings`, `provenance: dict[tuple[str,str],str]`, `target_arch: str`, `profiles: ResolvedDebugProfiles`, `fragments: tuple[str,...]`, `effective_debuggee: DebuggeeCfg`, `runtime_defaults: dict[str,str]`, `runtime_overrides: tuple[str,...]`, `extra_boot_args: tuple[str,...]`, `profile_warnings: tuple[str,...]`, `runtime_notes: tuple[str,...]`, `implied_by: dict[str, tuple[str,...]]`
  - `def resolve_run(*, profile_names: tuple[str,...], config: ConfigResolution, host: HostProfile, workspace: Path) -> RunResolution`
- Consumes: `load_profiles` (Task 5), `verify_config` types (Task 6), `ConfigResolution.effective_debuggee` (Task 3), `HostProfile.target_arch/accel/os` (Task 4).
- Compatibility: `kaslr` requires `CONFIG_RANDOMIZE_BASE`; if any resolved profile declares `CONFIG_RANDOMIZE_BASE` as hard `value="n"` AND effective `kaslr` is True with explicit (non-default/non-profile) provenance → raise `ConfigError`. A profile-default-on later turned off → runtime note "adds nokaslr".

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_debug_profiles_resolve.py
from pathlib import Path

import pytest

from likedbg.config import GeneralCfg, Settings, load_config
from likedbg.debug_profiles import resolve_run
from likedbg.errors import ConfigError
from likedbg.host_profile import HostProfile, Probes


def _probes(machine="x86_64", system="linux"):
    return Probes(system=lambda: system, machine=lambda: machine, kvm_accessible=lambda: False,
                  hvf_supported=lambda: False, native_qemu_present=lambda _a: True,
                  workspace_case_sensitive=lambda _p: True)


def _scaffold(tmp_path: Path, *, kaslr_line: str = "kaslr = false") -> None:
    (tmp_path / "configs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "default.toml").write_text(
        f'[source]\nkind="mmp"\nvalue="6.6.30"\n[debuggee]\n{kaslr_line}\n')
    pdir = tmp_path / "configs" / "profiles"
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\n'
        'fragments=["configs/fragments/generic.config","configs/fragments/no-kaslr.config"]\n'
        '[[expect]]\nsymbol="CONFIG_RANDOMIZE_BASE"\nvalue="n"\nseverity="hard"\n')
    (pdir / "crash-debug.toml").write_text(
        'name="crash-debug"\nkind="addon"\ndescription="d"\nfragments=["configs/fragments/profiles/crash-debug.config"]\n')
    (pdir / "kasan.toml").write_text(
        'name="kasan"\nkind="addon"\ndescription="d"\nimplies=["crash-debug"]\n'
        'fragments=["configs/fragments/profiles/kasan.config"]\n'
        '[[expect]]\nsymbol="CONFIG_KASAN"\nvalue="y"\nseverity="hard"\n')


def _host(tmp_path):
    return HostProfile.detect(Settings(general=GeneralCfg(arch="native")), tmp_path, _probes())


def test_kasan_implies_crash_debug_and_orders_fragments(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    rr = resolve_run(profile_names=("kasan",), config=cfg, host=_host(tmp_path), workspace=tmp_path)
    assert rr.profiles.names == ("exploit-dev", "crash-debug", "kasan")
    assert rr.profiles.base == "exploit-dev"
    # base fragments first, then implied add-on, then the explicit add-on
    assert rr.fragments == (
        "configs/fragments/generic.config",
        "configs/fragments/no-kaslr.config",
        "configs/fragments/profiles/crash-debug.config",
        "configs/fragments/profiles/kasan.config",
    )
    assert rr.implied_by["crash-debug"] == ("kasan",)


def test_unknown_profile_errors(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError):
        resolve_run(profile_names=("asan",), config=cfg, host=_host(tmp_path), workspace=tmp_path)


def test_explicit_kaslr_on_with_exploit_dev_is_contradiction(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    # user explicitly turns kaslr on via local.toml → explicit provenance
    (tmp_path / "configs" / "local.toml").write_text("[debuggee]\nkaslr = true\n")
    cfg = load_config(tmp_path)
    with pytest.raises(ConfigError):
        resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host(tmp_path), workspace=tmp_path)


def test_default_kaslr_off_is_fine(tmp_path: Path) -> None:
    _scaffold(tmp_path)
    cfg = load_config(tmp_path)
    rr = resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host(tmp_path), workspace=tmp_path)
    assert rr.effective_debuggee.kaslr is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_debug_profiles_resolve.py -v`
Expected: FAIL (`ImportError: resolve_run`).

- [ ] **Step 3: Write minimal implementation**

Append to `debug_profiles.py` (add imports `from likedbg.config import ConfigResolution, DebuggeeCfg, Settings, LAYER_CLI, LAYER_LOCAL, LAYER_SCENARIO` and `from likedbg.host_profile import HostProfile`):

```python
_EXPLICIT_LAYERS = frozenset({LAYER_LOCAL, LAYER_SCENARIO, LAYER_CLI})
# Runtime toggle → build symbol it requires to be enable-able.
_TOGGLE_REQUIRES = {"kaslr": "CONFIG_RANDOMIZE_BASE"}


@dataclass(frozen=True)
class RunResolution:
    requested_settings: Settings
    provenance: dict[tuple[str, str], str]
    target_arch: str
    profiles: ResolvedDebugProfiles
    fragments: tuple[str, ...]
    effective_debuggee: DebuggeeCfg
    runtime_defaults: dict[str, str]
    runtime_overrides: tuple[str, ...]
    extra_boot_args: tuple[str, ...]
    profile_warnings: tuple[str, ...]
    runtime_notes: tuple[str, ...]
    implied_by: dict[str, tuple[str, ...]]


def _expand(profile_names: tuple[str, ...], registry: dict[str, ProfileDef]) -> tuple[
    list[str], str, dict[str, list[str]]
]:
    """Return (ordered resolved names, base, implied_by) — base first, implied add-ons, explicit add-ons."""
    for n in profile_names:
        if n not in registry:
            choices = ", ".join(sorted(registry))
            raise ConfigError(f"unknown debug profile {n!r}", remedy=f"choose one of {choices}")
    requested_bases = [n for n in profile_names if registry[n].kind == "base"]
    if len(requested_bases) > 1:
        raise ConfigError(
            f"multiple base profiles requested: {', '.join(requested_bases)}",
            remedy="choose exactly one base profile (e.g. exploit-dev OR hardened)",
        )
    base = requested_bases[0] if requested_bases else "exploit-dev"
    if base not in registry:
        raise ConfigError(f"base profile {base!r} not found", remedy="add configs/profiles/exploit-dev.toml")
    explicit_addons = [n for n in profile_names if registry[n].kind == "addon"]
    implied_by: dict[str, list[str]] = {}
    implied: list[str] = []
    for n in explicit_addons:
        for imp in registry[n].implies:
            if registry[imp].kind != "addon":
                continue
            implied_by.setdefault(imp, []).append(n)
            if imp not in implied and imp not in explicit_addons:
                implied.append(imp)
    ordered = [base, *implied, *[a for a in explicit_addons if a not in implied]]
    # de-dupe preserving order
    seen: dict[str, None] = {}
    for n in ordered:
        seen.setdefault(n, None)
    return list(seen), base, implied_by


def _selectors_match(*, arch=None, accel=None, host_os=None, profiles=None, active, host) -> bool:
    if arch is not None and host.target_arch not in arch:
        return False
    if accel is not None and host.accel not in accel:
        return False
    if host_os is not None and host.os not in host_os:
        return False
    if profiles is not None and not set(profiles).issubset(active):
        return False
    return True


def resolve_run(
    *, profile_names: tuple[str, ...], config: ConfigResolution, host: HostProfile, workspace: Path
) -> RunResolution:
    registry = load_profiles(workspace)
    ordered, base, implied_by_lists = _expand(profile_names, registry)
    active = set(ordered)
    defs = [registry[n] for n in ordered]

    fragments = tuple(f for d in defs for f in d.fragments)
    expectations = tuple(e for d in defs for e in d.expect)

    # Profile runtime defaults (layer 4) — later profiles win on conflict.
    runtime_defaults: dict[str, str] = {}
    for d in defs:
        for k, v in d.runtime_defaults.debuggee.items():
            runtime_defaults[k] = "true" if v is True else "false" if v is False else str(v)

    effective_debuggee, eff_prov = config.effective_debuggee(runtime_defaults)

    warnings: list[str] = []
    for d in defs:
        for w in d.warning:
            if _selectors_match(arch=w.arch, accel=w.accel, host_os=w.host_os, profiles=w.profiles,
                                active=active, host=host):
                warnings.append(w.message)

    boot_args: list[str] = []
    runtime_notes: list[str] = []
    for d in defs:
        for ba in d.boot_arg:
            if ba.kernel_min is not None or ba.kernel_max is not None:
                runtime_notes.append(f"deferred version-gated boot arg {ba.value!r} (B1 does not evaluate kernel_min/max)")
                continue
            if _selectors_match(arch=ba.arch, profiles=ba.profiles, active=active, host=host):
                boot_args.append(ba.value)

    # Compatibility: resolution-time contradictions (Q12).
    overrides: list[str] = []
    for toggle, symbol in _TOGGLE_REQUIRES.items():
        wants_on = bool(getattr(effective_debuggee, toggle))
        forbidden_hard = any(
            e.symbol == symbol and e.value == "n" and e.severity == "hard"
            and _expect_applies(e, target_arch=host.target_arch, kernel_release=None)
            for e in expectations
        )
        prov = eff_prov.get(("debuggee", toggle))
        explicit = prov in _EXPLICIT_LAYERS
        if wants_on and forbidden_hard:
            if explicit:
                raise ConfigError(
                    f"[debuggee] {toggle}=on is impossible: active profiles build {symbol} disabled",
                    remedy="remove the explicit toggle, or switch to a base profile that builds it in (e.g. hardened)",
                )
        if not wants_on and prov == "profile":
            overrides.append(f"runtime override: {toggle} off → adds nokaslr (profile default was on)")

    resolved = ResolvedDebugProfiles(
        names=tuple(ordered), base=base, expected_config=expectations, future_breakpoint_groups=()
    )
    return RunResolution(
        requested_settings=config.settings,
        provenance=eff_prov,
        target_arch=host.target_arch,
        profiles=resolved,
        fragments=fragments,
        effective_debuggee=effective_debuggee,
        runtime_defaults=runtime_defaults,
        runtime_overrides=tuple(overrides),
        extra_boot_args=tuple(boot_args),
        profile_warnings=tuple(warnings),
        runtime_notes=tuple(runtime_notes),
        implied_by={k: tuple(v) for k, v in implied_by_lists.items()},
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_debug_profiles_resolve.py -v && uv run mypy src/likedbg/debug_profiles.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/debug_profiles.py src/tests/test_debug_profiles_resolve.py
git commit -m "feat(debug_profiles): resolve_run with ordering, implications, compat checks, effective toggles"
```

---

# Phase 3 — Cache & Build

## Task 8: `build_recipe(arch=...)` + patch hashes + `Manifest` fields

**Files:**
- Modify: `src/likedbg/cache.py` (`BuildRecipe`, `build_recipe`, `Manifest`)
- Test: `src/tests/test_kernel_builder.py` (extend) + `src/tests/test_cache.py` if present

**Interfaces:**
- Produces: `build_recipe(settings, *, version, arch, workspace, fragments, patch_dirs=()) -> BuildRecipe`; `BuildRecipe.patch_hashes: tuple[tuple[str,str],...]`; `BuildRecipe.kernel_tag` stays; `Manifest.kernel_release: str = ""`, `Manifest.paths["config_host"]`.
- Consumes: `input_hash.hash_tree` (Task 1).
- Note: `arch` is now explicit (`host.target_arch`); cache identity/label use it, not `settings.general.arch` (which may be `native`).

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_cache.py  (add)
from pathlib import Path

from likedbg.cache import build_recipe
from likedbg.config import BuildCfg, GeneralCfg, Settings


def test_build_recipe_uses_explicit_arch_not_native(tmp_path: Path) -> None:
    (tmp_path / "configs" / "fragments").mkdir(parents=True)
    frag = "configs/fragments/generic.config"
    (tmp_path / frag).write_text("CONFIG_X=y\n")
    s = Settings(general=GeneralCfg(arch="native"))
    r = build_recipe(s, version="6.6.30", arch="arm64", workspace=tmp_path, fragments=[frag])
    assert r.arch == "arm64"
    assert r.label.startswith("linux-6.6.30-")


def test_patch_dir_changes_cache_key(tmp_path: Path) -> None:
    (tmp_path / "configs" / "fragments").mkdir(parents=True)
    frag = "configs/fragments/generic.config"
    (tmp_path / frag).write_text("CONFIG_X=y\n")
    patches = tmp_path / "patches" / "uaf"
    patches.mkdir(parents=True)
    (patches / "0001.patch").write_text("--- a\n+++ b\n")
    s = Settings(build=BuildCfg(patch_dirs=("patches/uaf",)))
    r1 = build_recipe(s, version="6.6.30", arch="x86_64", workspace=tmp_path, fragments=[frag],
                      patch_dirs=("patches/uaf",))
    (patches / "0001.patch").write_text("--- a\n+++ b\n+changed\n")
    r2 = build_recipe(s, version="6.6.30", arch="x86_64", workspace=tmp_path, fragments=[frag],
                      patch_dirs=("patches/uaf",))
    assert r1.key != r2.key
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_cache.py -v`
Expected: FAIL (`build_recipe() got an unexpected keyword argument 'arch'`).

- [ ] **Step 3: Write minimal implementation**

In `cache.py`: add `from likedbg.input_hash import hash_tree`. Add field to `BuildRecipe` and extend `cache_inputs`:

```python
@dataclass(frozen=True)
class BuildRecipe:
    version: str
    arch: str
    compiler: str
    make_vars: tuple[tuple[str, str], ...]
    frag_hashes: tuple[tuple[str, str], ...]
    fragments: tuple[str, ...]
    patch_hashes: tuple[tuple[str, str], ...] = ()
    kernel_tag: str = ""

    def env(self) -> dict[str, str]:
        return dict(self.make_vars)

    def cache_inputs(self) -> dict[str, str]:
        inputs = {"version": self.version, "arch": self.arch, "compiler": self.compiler, "kernel_tag": self.kernel_tag}
        inputs.update({f"frag:{name}": h for name, h in self.frag_hashes})
        inputs.update({f"patch:{name}": h for name, h in self.patch_hashes})
        return inputs
```

Replace `build_recipe`:

```python
def build_recipe(
    settings: Settings, *, version: str, arch: str, workspace: Path, fragments: list[str],
    patch_dirs: tuple[str, ...] = (),
) -> BuildRecipe:
    tc = resolve_toolchain(settings.build.compiler, arch)
    frag_hashes = sorted((rel, hashlib.sha256((workspace / rel).read_bytes()).hexdigest()) for rel in fragments)
    patch_hashes = tuple((rel, hash_tree(workspace / rel).aggregate) for rel in patch_dirs)  # TOML list order
    return BuildRecipe(
        version=version,
        arch=arch,
        compiler=settings.build.compiler,
        make_vars=tuple(sorted(tc.make_vars.items())),
        frag_hashes=tuple(frag_hashes),
        fragments=tuple(fragments),
        patch_hashes=patch_hashes,
        kernel_tag=settings.build.label_suffix,
    )
```

Add to `Manifest` dataclass: `kernel_release: str = ""` (after `arch`). (`rootfs_recipe` still reads `settings.rootfs.*` and `settings.general.arch`; change its `arch=settings.general.arch` to accept an explicit `arch` param mirroring `build_recipe` — see Task 13 wiring. For now add `arch` param with default `settings.general.arch` for back-compat: `def rootfs_recipe(settings, *, arch=None, workspace=None)` using `arch or settings.general.arch`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_cache.py -v && uv run mypy src/likedbg/cache.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cache.py src/tests/test_cache.py
git commit -m "feat(cache): explicit arch param, patch-dir hashes in build identity, Manifest.kernel_release"
```

---

## Task 9: `BuildStage` — apply patches + capture `.config`/`kernel_release`

**Files:**
- Modify: `src/likedbg/stages/build.py`
- Test: `src/tests/test_kernel_builder.py` (extend with a fake `ContainerService`)

**Interfaces:**
- Consumes: `BuildRecipe.patch_hashes`/`fragments`; needs `patch_dirs` to apply → add `patch_dirs: tuple[str,...]` ctor arg.
- Produces (manifest): `paths["config_host"]` (host file path), `kernel_release`. On fresh build copies `.config` to `artifacts/<label>/config` and reads Makefile release inside the container; writes both into the manifest. On cache hit, reads them from the manifest (no container).
- Records the `make` command via optional `ctx.recorder` (Task 11 wires recorder onto ctx; guard with `getattr`).

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_kernel_builder.py  (add — uses a recording fake container)
from pathlib import Path

from likedbg.cache import build_recipe
from likedbg.config import Settings
from likedbg.host_profile import HostProfile, Probes
from likedbg.pipeline import PipelineContext
from likedbg.stages.build import BuildStage


class _FakeContainer:
    def __init__(self) -> None:
        self.cmds: list[str] = []

    def run_detached(self, *a, **k):  # noqa: ANN
        return "c1"

    def exec(self, c, cmd, workdir=None):  # noqa: ANN
        self.cmds.append(cmd)
        class _R:  # noqa
            output = "VERSION = 6\nPATCHLEVEL = 6\nSUBLEVEL = 30\nEXTRAVERSION =\n" if "Makefile" in cmd else ""
        return _R()

    def stop(self, c):  # noqa: ANN
        pass


def _host(tmp_path):
    p = Probes(system=lambda: "linux", machine=lambda: "x86_64", kvm_accessible=lambda: False,
               hvf_supported=lambda: False, native_qemu_present=lambda _a: True,
               workspace_case_sensitive=lambda _p: True)
    return HostProfile.detect(Settings(), tmp_path, p)


def test_patches_applied_in_order(tmp_path: Path) -> None:
    (tmp_path / "configs" / "fragments").mkdir(parents=True)
    frag = "configs/fragments/generic.config"
    (tmp_path / frag).write_text("CONFIG_X=y\n")
    patches = tmp_path / "patches" / "uaf"
    patches.mkdir(parents=True)
    (patches / "0001-a.patch").write_text("p1")
    (patches / "0002-b.patch").write_text("p2")
    r = build_recipe(Settings(), version="6.6.30", arch="x86_64", workspace=tmp_path,
                     fragments=[frag], patch_dirs=("patches/uaf",))
    fake = _FakeContainer()
    stage = BuildStage(fake, recipe=r, kbuilder_image="img", workspace=tmp_path,
                       kernel_volume="vol", patch_dirs=("patches/uaf",))
    ctx = PipelineContext(settings=Settings(), host=_host(tmp_path), build_label=r.label)
    stage.run(ctx)
    patch_cmds = [c for c in fake.cmds if "patch -p1" in c or "git apply" in c]
    assert len(patch_cmds) == 2  # one per patch file, sorted
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_kernel_builder.py -k patches -v`
Expected: FAIL (`BuildStage.__init__() got an unexpected keyword argument 'patch_dirs'`).

- [ ] **Step 3: Write minimal implementation**

In `build.py`: add `patch_dirs: tuple[str, ...] = ()` to `__init__` (store `self._patch_dirs`). After the `defconfig` step and before `merge_config`, insert patch application; after `make all`, capture `.config` + release. Concretely, inside `run()` fresh-build branch, after `mrproper`/before `defconfig`:

```python
            # Apply patches against the unpacked source tree (TOML list order; files sorted).
            for rel in self._patch_dirs:
                pdir = self._workspace / rel
                for pf in sorted(p for p in pdir.rglob("*") if p.is_file() and p.suffix in {".patch", ".diff"}):
                    container_patch = f"{_MOUNT}/{pf.relative_to(self._workspace).as_posix()}"
                    self._c.exec(container, f"patch -p1 -i {container_patch}", workdir=root)
```

After `make all` (and the optional chown), capture config + release:

```python
            release = self._c.exec(
                container, f"sed -n '1,6p' {root}/Makefile", workdir=root
            ).output
            from likedbg.debug_profiles import parse_kernel_release
            kernel_release = parse_kernel_release(release)
            export_dir = self._workspace / "artifacts" / label
            export_dir.mkdir(parents=True, exist_ok=True)
            config_host = export_dir / "config"
            config_text = self._c.exec(container, f"cat {root}/.config", workdir=root).output
            config_host.write_text(config_text)
```

Then add `kernel_release=kernel_release` and `paths["config_host"]=str(config_host)` to the `write_manifest` call. Record the build command if a recorder is present:

```python
        recorder = getattr(ctx, "recorder", None)
        if recorder is not None:
            recorder.record_command("qemu", shell="", argv=[])  # no-op placeholder removed in Task 12
```

(Remove the placeholder line — build does not record a launch command; it only needs to *not* crash on the new ctx field. The real command recording is in Debuggee/Debugger stages, Task 12.) On the **cache-hit** branch, set `ctx.kernel_release` and `ctx.config_host` from the loaded manifest fields (add those two optional fields to `PipelineContext` in Task 10). For a legacy manifest missing `config_host`, spin a one-time helper container to `cat` the in-tree `.config`, write it to `artifacts/<label>/config`, and backfill the manifest (`write_manifest`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_kernel_builder.py -v && uv run mypy src/likedbg/stages/build.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/build.py src/tests/test_kernel_builder.py
git commit -m "feat(build): apply patch_dirs in order; capture .config + kernel_release to host/manifest"
```

---

# Phase 4 — Verification Stage & Pipeline Context

## Task 10: `PipelineContext` fields + config reader

**Files:**
- Modify: `src/likedbg/pipeline.py` (`PipelineContext`)
- Create: `src/likedbg/stages/profile_verification.py` (config reader helper `read_built_config`)
- Test: `src/tests/test_profile_verification.py` (reader part)

**Interfaces:**
- Produces: `PipelineContext` new optional fields `run_resolution`, `effective_debuggee`, `extra_boot_args: tuple[str,...] = ()`, `recorder`, `kernel_release: str | None`, `config_host: Path | None`; `read_built_config(manifest, *, container, workspace) -> tuple[str, str]` returning `(config_text, kernel_release)`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_profile_verification.py
from pathlib import Path

from likedbg.cache import Manifest
from likedbg.stages.profile_verification import read_built_config


def test_reads_host_config_without_container(tmp_path: Path) -> None:
    cfg = tmp_path / "artifacts" / "lbl" / "config"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("CONFIG_KASAN=y\n")
    m = Manifest(kind="build", label="lbl", key="k", version="6.6.30", arch="x86_64",
                 storage_mode="volume", kernel_release="6.6.30",
                 paths={"config_host": str(cfg)})
    text, release = read_built_config(m, container=None, workspace=tmp_path)
    assert "CONFIG_KASAN=y" in text and release == "6.6.30"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_profile_verification.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Write minimal implementation**

`pipeline.py` — add fields to `PipelineContext` (keep additions at the end, all defaulted):

```python
    run_resolution: object | None = None      # debug_profiles.RunResolution (avoid import cycle)
    effective_debuggee: object | None = None   # config.DebuggeeCfg
    extra_boot_args: tuple[str, ...] = ()
    recorder: object | None = None             # run_artifacts.RunRecorder
    kernel_release: str | None = None
    config_host: Path | None = None
```

`stages/profile_verification.py`:

```python
"""ProfileVerificationStage: verify the built .config against resolved Debug profile expectations.
Reads host-captured .config + kernel_release (zero per-run containers); legacy manifests fall back
to a one-time helper-container read + backfill."""

from __future__ import annotations

from pathlib import Path

from likedbg import cache
from likedbg.cache import Manifest
from likedbg.constants import BASE_IMAGE, VOLUME_MOUNT


def read_built_config(manifest: Manifest, *, container, workspace: Path) -> tuple[str, str]:  # noqa: ANN001
    config_host = manifest.paths.get("config_host")
    if config_host and Path(config_host).is_file():
        return Path(config_host).read_text(), manifest.kernel_release
    # Legacy fallback: read from the tree via a helper container, backfill the manifest.
    root = manifest.paths["kernel_root"]
    if container is None:
        raise cache.CacheError(f"no captured .config for {manifest.label}", remedy="rebuild without --use")
    if manifest.storage_mode == "volume":
        c = container.run_detached(BASE_IMAGE, volumes={cache.KERNEL_VOLUME: {"bind": VOLUME_MOUNT, "mode": "ro"}},
                                   detach=True, tty=True)
    else:
        src = cache.tree_mount_source(workspace, storage_mode=manifest.storage_mode)
        c = container.run_detached(BASE_IMAGE, volumes={src: {"bind": VOLUME_MOUNT, "mode": "ro"}}, detach=True, tty=True)
    try:
        text = container.exec(c, f"cat {root}/.config").output
        from likedbg.debug_profiles import parse_kernel_release
        release = manifest.kernel_release or parse_kernel_release(container.exec(c, f"sed -n '1,6p' {root}/Makefile").output)
    finally:
        container.stop(c)
    export = workspace / "artifacts" / manifest.label / "config"
    export.parent.mkdir(parents=True, exist_ok=True)
    export.write_text(text)
    return text, release
```

(`cache.CacheError` is re-exported via `from likedbg.errors import CacheError` in cache.py; if not, import `from likedbg.errors import CacheError` here.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_profile_verification.py -v && uv run mypy src/likedbg/stages/profile_verification.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/pipeline.py src/likedbg/stages/profile_verification.py src/tests/test_profile_verification.py
git commit -m "feat(pipeline): RunResolution/effective ctx fields + host-side .config reader"
```

---

## Task 11: `ProfileVerificationStage`

**Files:**
- Modify: `src/likedbg/stages/profile_verification.py` (add the stage class)
- Test: `src/tests/test_profile_verification.py` (extend)

**Interfaces:**
- Produces: `ProfileVerificationStage(container, *, workspace, kernel_volume)`; `run` reads `ctx.run_resolution` + manifest, calls `verify_config`, records via `ctx.recorder.record_profile_verification(...)` when present, copies `.config` to run artifacts, raises `BuildError` on `missing_hard`, sets status `profile-verification-failed` first.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_profile_verification.py  (add)
import pytest

from likedbg.config import Settings
from likedbg.debug_profiles import Expect, ResolvedDebugProfiles, RunResolution
from likedbg.errors import BuildError
from likedbg.host_profile import HostProfile, Probes
from likedbg.pipeline import PipelineContext
from likedbg.stages.profile_verification import ProfileVerificationStage
from likedbg.cache import Manifest, write_manifest


def _rr(*exp):
    return RunResolution(requested_settings=Settings(), provenance={}, target_arch="x86_64",
                         profiles=ResolvedDebugProfiles(names=("exploit-dev",), base="exploit-dev",
                                                        expected_config=tuple(exp), future_breakpoint_groups=()),
                         fragments=(), effective_debuggee=Settings().debuggee, runtime_defaults={},
                         runtime_overrides=(), extra_boot_args=(), profile_warnings=(), runtime_notes=(), implied_by={})


def _host(tmp_path):
    p = Probes(system=lambda: "linux", machine=lambda: "x86_64", kvm_accessible=lambda: False,
               hvf_supported=lambda: False, native_qemu_present=lambda _a: True, workspace_case_sensitive=lambda _p: True)
    return HostProfile.detect(Settings(), tmp_path, p)


def _seed(tmp_path: Path, body: str) -> Manifest:
    cfg = tmp_path / "artifacts" / "lbl" / "config"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(body)
    m = Manifest(kind="build", label="lbl", key="k", version="6.6.30", arch="x86_64", storage_mode="volume",
                 kernel_release="6.6.30", paths={"config_host": str(cfg)})
    write_manifest(tmp_path, m)
    return m


def test_hard_failure_raises_build_error(tmp_path: Path) -> None:
    _seed(tmp_path, "# CONFIG_KASAN is not set\n")
    stage = ProfileVerificationStage(None, workspace=tmp_path, kernel_volume="vol")
    ctx = PipelineContext(settings=Settings(), host=_host(tmp_path), build_label="lbl",
                          run_resolution=_rr(Expect(symbol="CONFIG_KASAN", value="y", severity="hard")))
    with pytest.raises(BuildError):
        stage.run(ctx)


def test_pass_returns_ctx(tmp_path: Path) -> None:
    _seed(tmp_path, "CONFIG_KASAN=y\n")
    stage = ProfileVerificationStage(None, workspace=tmp_path, kernel_volume="vol")
    ctx = PipelineContext(settings=Settings(), host=_host(tmp_path), build_label="lbl",
                          run_resolution=_rr(Expect(symbol="CONFIG_KASAN", value="y", severity="hard")))
    assert stage.run(ctx) is ctx
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_profile_verification.py -k "hard_failure or pass_returns" -v`
Expected: FAIL (`ImportError: ProfileVerificationStage`).

- [ ] **Step 3: Write minimal implementation**

Append to `profile_verification.py`:

```python
from likedbg.debug_profiles import RunResolution, verify_config
from likedbg.errors import BuildError
from likedbg.pipeline import PipelineContext


class ProfileVerificationStage:
    name = "profile-verification"

    def __init__(self, container, *, workspace: Path, kernel_volume: str) -> None:  # noqa: ANN001
        self._c = container
        self._workspace = workspace
        self._volume = kernel_volume

    def should_skip(self, ctx: PipelineContext) -> bool:
        return ctx.run_resolution is None

    def run(self, ctx: PipelineContext) -> PipelineContext:
        rr = ctx.run_resolution
        assert isinstance(rr, RunResolution)
        manifest = cache.load_manifest(self._workspace, "build", ctx.build_label or "")
        config_text, release = read_built_config(manifest, container=self._c, workspace=self._workspace)
        ctx.kernel_release = release
        verification = verify_config(config_text, rr.profiles, target_arch=rr.target_arch, kernel_release=release)
        recorder = ctx.recorder
        if recorder is not None:
            recorder.record_profile_verification(verification)  # type: ignore[attr-defined]
            recorder.record_kernel_paths(config=manifest.paths.get("config_host", ""),  # type: ignore[attr-defined]
                                         system_map=manifest.paths.get("gdb_vmlinux", ""),
                                         vmlinux=manifest.paths.get("gdb_vmlinux", ""),
                                         image=manifest.paths.get("image_host", ""))
        if verification.missing_hard:
            if recorder is not None:
                recorder.set_status("profile-verification-failed",  # type: ignore[attr-defined]
                                    message="; ".join(f"{e.symbol}={e.value}" for e in verification.missing_hard))
            first = verification.missing_hard[0]
            raise BuildError(
                f"debug profile verification failed: {rr.profiles.names} requested {first.symbol}={first.value}, "
                f"but the final .config does not satisfy it",
                remedy="inspect artifacts/runs/latest/profiles.json or remove the offending profile",
            )
        for msg in verification.warnings:
            from loguru import logger
            logger.warning(msg)
        return ctx
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_profile_verification.py -v && uv run mypy src/likedbg/stages/profile_verification.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/profile_verification.py src/tests/test_profile_verification.py
git commit -m "feat(stage): ProfileVerificationStage with hard/soft verdicts and recorder hooks"
```

---

# Phase 5 — Run Artifacts

## Task 12: `RunRecorder`

**Files:**
- Create: `src/likedbg/run_artifacts.py`
- Modify: `src/likedbg/logsetup.py` (`add_run_logfile(workspace, *, path=None)`)
- Test: `src/tests/test_run_artifacts.py`

**Interfaces:**
- Produces: `RunStatus = Literal["created","profile-verification-failed","launching","launched","launch-failed"]`; `RunRecorder.start(*, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles) -> RunRecorder`; methods `set_status`, `add_warning`, `record_command`, `record_profile_verification`, `record_kernel_paths`; properties `run_dir`, `likedbg_log`, `debuggee_pane_log`, `debugger_pane_log`.
- Behavior: `start` creates the dir tree, writes `run.json`(`created`), `settings.requested.json`, `settings.effective.json`, `host.json`, `profiles.json`, copies resolved profile TOMLs + fragments preserving relative paths, points `artifacts/runs/latest` and `artifacts/logs/latest.log`. Atomic `run.json` writes with `status_history`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_run_artifacts.py
import json
from pathlib import Path

from likedbg.config import Settings
from likedbg.debug_profiles import ResolvedDebugProfiles, RunResolution
from likedbg.host_profile import HostProfile, Probes
from likedbg.run_artifacts import RunRecorder


def _rr() -> RunResolution:
    return RunResolution(requested_settings=Settings(), provenance={("debuggee", "kaslr"): "default"},
                         target_arch="arm64",
                         profiles=ResolvedDebugProfiles(names=("exploit-dev",), base="exploit-dev",
                                                        expected_config=(), future_breakpoint_groups=()),
                         fragments=(), effective_debuggee=Settings().debuggee, runtime_defaults={},
                         runtime_overrides=(), extra_boot_args=(), profile_warnings=(), runtime_notes=(), implied_by={})


def _host(tmp_path):
    p = Probes(system=lambda: "darwin", machine=lambda: "arm64", kvm_accessible=lambda: False,
               hvf_supported=lambda: True, native_qemu_present=lambda _a: True, workspace_case_sensitive=lambda _p: False)
    return HostProfile.detect(Settings(), tmp_path, p)


def test_start_creates_layout_and_latest(tmp_path: Path) -> None:
    rec = RunRecorder.start(workspace=tmp_path, requested_settings=Settings(), run_resolution=_rr(),
                            host=_host(tmp_path), build_label="linux-6.6.30-abcd1234",
                            rootfs_label="rootfs-arm64-bookworm-deadbeef", profiles=_rr().profiles)
    assert rec.run_dir.is_dir()
    run = json.loads((rec.run_dir / "run.json").read_text())
    assert run["status"] == "created" and run["schema_version"] == 1
    assert (rec.run_dir / "settings.requested.json").is_file()
    assert (rec.run_dir / "profiles.json").is_file()
    latest = tmp_path / "artifacts" / "runs" / "latest"
    assert latest.exists()  # symlink or text fallback


def test_record_command_writes_argv_and_shell(tmp_path: Path) -> None:
    rec = RunRecorder.start(workspace=tmp_path, requested_settings=Settings(), run_resolution=_rr(),
                            host=_host(tmp_path), build_label="b", rootfs_label="r", profiles=_rr().profiles)
    rec.record_command("qemu", shell="qemu-system-aarch64 ...", argv=["qemu-system-aarch64", "-M", "virt"])
    assert (rec.run_dir / "commands" / "qemu.sh").read_text().startswith("qemu-system-aarch64")
    assert json.loads((rec.run_dir / "commands" / "qemu.argv.json").read_text())[1] == "-M"


def test_set_status_appends_history(tmp_path: Path) -> None:
    rec = RunRecorder.start(workspace=tmp_path, requested_settings=Settings(), run_resolution=_rr(),
                            host=_host(tmp_path), build_label="b", rootfs_label="r", profiles=_rr().profiles)
    rec.set_status("launched")
    run = json.loads((rec.run_dir / "run.json").read_text())
    assert run["status"] == "launched"
    assert [h["status"] for h in run["status_history"]] == ["created", "launched"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_run_artifacts.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Write minimal implementation**

`logsetup.add_run_logfile` — change signature to `def add_run_logfile(workspace: Path, *, path: Path | None = None) -> Path:` and, when `path` is given, use it directly (create parent, `logger.add(path, ...)`, point `latest.log` at it) instead of synthesizing a name. Keep the no-`path` behavior for any remaining callers.

`run_artifacts.py`:

```python
"""RunRecorder: the runtime seam. Owns artifacts/runs/<run-id>/ — its layout, run.json status
machine, and the resolved-profile/fragment snapshots. Callers get paths, not directory knowledge."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from likedbg.config import Settings
from likedbg.host_profile import HostProfile

RunStatus = Literal["created", "profile-verification-failed", "launching", "launched", "launch-failed"]
SCHEMA_VERSION = 1


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_id(build_label: str) -> str:
    return f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{build_label}"


def _point(link: Path, target: Path) -> None:
    try:
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(target.name if link.parent == target.parent else target)
    except OSError:
        link.with_suffix(".txt").write_text(str(target))


class RunRecorder:
    def __init__(self, run_dir: Path, run_json: dict) -> None:  # noqa: ANN001
        self._dir = run_dir
        self._run = run_json

    @property
    def run_dir(self) -> Path:
        return self._dir

    @property
    def likedbg_log(self) -> Path:
        return self._dir / "logs" / "likedbg.log"

    @property
    def debuggee_pane_log(self) -> Path:
        return self._dir / "logs" / "debuggee-pane.log"

    @property
    def debugger_pane_log(self) -> Path:
        return self._dir / "logs" / "debugger-pane.log"

    @classmethod
    def start(cls, *, workspace: Path, requested_settings: Settings, run_resolution, host: HostProfile,  # noqa: ANN001
              build_label: str, rootfs_label: str, profiles) -> RunRecorder:
        run_id = _run_id(build_label)
        run_dir = workspace / "artifacts" / "runs" / run_id
        for sub in ("logs", "commands", "kernel", "profiles", "fragments"):
            (run_dir / sub).mkdir(parents=True, exist_ok=True)
        # requested + effective settings
        (run_dir / "settings.requested.json").write_text(requested_settings.model_dump_json(indent=2))
        effective = requested_settings.model_dump()
        effective["debuggee"] = run_resolution.effective_debuggee.model_dump()
        effective["_provenance"] = _provenance_json(run_resolution.provenance)
        (run_dir / "settings.effective.json").write_text(json.dumps(effective, indent=2, sort_keys=True))
        (run_dir / "host.json").write_text(json.dumps(host.__dict__, indent=2, sort_keys=True))
        _write_profiles_json(run_dir, workspace, run_resolution, profiles)
        run_json = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "kind": "debugging-session",
            "status": "created",
            "created_at": _utc_now(),
            "build_label": build_label,
            "rootfs_label": rootfs_label,
            "host": "host.json",
            "settings_requested": "settings.requested.json",
            "settings_effective": "settings.effective.json",
            "profiles": "profiles.json",
            "commands": {"qemu": "commands/qemu.sh", "gdb": "commands/gdb.sh"},
            "logs": {"likedbg": "logs/likedbg.log", "debuggee": "logs/debuggee-pane.log",
                     "debugger": "logs/debugger-pane.log"},
            "warnings": [w for w in run_resolution.profile_warnings],
            "status_history": [{"status": "created", "at": _utc_now()}],
        }
        rec = cls(run_dir, run_json)
        rec._flush()
        _point(workspace / "artifacts" / "runs" / "latest", run_dir)
        return rec

    def _flush(self) -> None:
        path = self._dir / "run.json"
        fd, tmp = tempfile.mkstemp(dir=str(self._dir), suffix=".json.tmp")
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps(self._run, indent=2, sort_keys=True))
        Path(tmp).replace(path)

    def set_status(self, status: RunStatus, *, message: str | None = None) -> None:
        self._run["status"] = status
        entry = {"status": status, "at": _utc_now()}
        if message:
            entry["message"] = message
        self._run["status_history"].append(entry)
        self._flush()

    def add_warning(self, code: str, message: str) -> None:
        self._run["warnings"].append({"at": _utc_now(), "code": code, "message": message})
        self._flush()

    def record_command(self, kind: Literal["qemu", "gdb"], *, shell: str, argv: list[str]) -> None:
        (self._dir / "commands" / f"{kind}.sh").write_text(shell + "\n")
        (self._dir / "commands" / f"{kind}.argv.json").write_text(json.dumps(argv, indent=2))

    def record_profile_verification(self, verification) -> None:  # noqa: ANN001
        payload = {
            "satisfied": [e.symbol for e in verification.satisfied],
            "missing_hard": [e.symbol for e in verification.missing_hard],
            "missing_soft": [e.symbol for e in verification.missing_soft],
            "warnings": list(verification.warnings),
        }
        (self._dir / "profiles" / "verification.json").write_text(json.dumps(payload, indent=2))

    def record_kernel_paths(self, *, config, system_map, vmlinux, image) -> None:  # noqa: ANN001
        kdir = self._dir / "kernel"
        if config and Path(str(config)).is_file():
            shutil.copyfile(str(config), kdir / "config")
        (kdir / "System.map.pointer").write_text(str(system_map))
        (kdir / "vmlinux.pointer").write_text(str(vmlinux))
        (kdir / "image.pointer").write_text(str(image))


def _provenance_json(prov: dict[tuple[str, str], str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for (section, key), layer in prov.items():
        out.setdefault(section, {})[key] = layer
    return out


def _write_profiles_json(run_dir: Path, workspace: Path, rr, profiles) -> None:  # noqa: ANN001
    def _snapshot(rel: str, subdir: str) -> dict:
        src = workspace / rel
        dest = run_dir / subdir / rel
        sha = ""
        if src.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)
            from likedbg.input_hash import hash_file
            sha = hash_file(src)
        return {"source": rel, "snapshot": f"{subdir}/{rel}", "sha256": sha}

    profile_files = [_snapshot(f"configs/profiles/{n}.toml", "profiles") for n in profiles.names]
    fragments = [_snapshot(rel, "fragments") for rel in rr.fragments]
    payload = {
        "requested": list(rr.profiles.names),  # resolution graph; requested set recorded in settings
        "base": profiles.base,
        "resolved": list(profiles.names),
        "implied_by": {k: list(v) for k, v in rr.implied_by.items()},
        "profile_files": profile_files,
        "fragments": fragments,
        "warnings": list(rr.profile_warnings),
        "runtime_notes": list(rr.runtime_notes) + list(rr.runtime_overrides),
    }
    (run_dir / "profiles.json").write_text(json.dumps(payload, indent=2, sort_keys=True))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_run_artifacts.py -v && uv run mypy src/likedbg/run_artifacts.py src/likedbg/logsetup.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/run_artifacts.py src/likedbg/logsetup.py src/tests/test_run_artifacts.py
git commit -m "feat(run_artifacts): RunRecorder owning artifacts/runs/<run-id>/ + run-scoped logfile"
```

---

# Phase 6 — Transcript Capture

## Task 13: `Session.pipe_pane` + launch + restart re-pipe

**Files:**
- Modify: `src/likedbg/session.py` (add `pipe_pane`)
- Modify: `src/likedbg/cli.py` (`_SESSION_STATE_OPTIONS` + restart re-pipe — launch wiring lands in Task 16)
- Test: `src/tests/test_session.py` (extend; create if absent)

**Interfaces:**
- Produces: `Session.pipe_pane(self, *, pane: str, output: Path) -> None` running `tmux pipe-pane -o -t <pane> 'cat >> <quoted-output>'`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_session.py  (add)
import shlex
from pathlib import Path

from likedbg.session import Session


def test_pipe_pane_command(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    s = Session("LIKE-DBG", runner=lambda a: (calls.append(a) or 0))
    out = tmp_path / "logs" / "debuggee-pane.log"
    s.pipe_pane(pane="%4", output=out)
    assert calls[0][:4] == ["tmux", "pipe-pane", "-o", "-t"]
    assert calls[0][4] == "%4"
    assert calls[0][5] == f"cat >> {shlex.quote(str(out))}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_session.py -k pipe_pane -v`
Expected: FAIL (`AttributeError: pipe_pane`).

- [ ] **Step 3: Write minimal implementation**

In `session.py` (add `import shlex` and `from pathlib import Path`):

```python
    def pipe_pane(self, *, pane: str, output: Path) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        self._tmux("pipe-pane", "-o", "-t", pane, f"cat >> {shlex.quote(str(output))}")
```

In `cli.py`: add `"@likedbg_debuggee_pane_log"` to `_SESSION_STATE_OPTIONS`. In `cmd_restart_debuggee`, after the pane is respawned/recreated and before `select_pane`, re-establish the pipe:

```python
        pane_log = session.get_option("@likedbg_debuggee_pane_log")
        if pane_log and debuggee_pane:
            try:
                session.pipe_pane(pane=debuggee_pane, output=Path(pane_log))
            except LikeDbgError:
                pass
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_session.py -k pipe_pane -v && uv run mypy src/likedbg/session.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/session.py src/likedbg/cli.py src/tests/test_session.py
git commit -m "feat(session): pipe_pane primitive + restart-aware Debuggee transcript re-pipe"
```

---

# Phase 7 — QEMU/GDB Effective Threading

## Task 14: `build_qemu_argv` on effective_debuggee + target_arch + extra boot args

**Files:**
- Modify: `src/likedbg/qemu.py`
- Modify: `src/likedbg/stages/download.py` (`resolve_version(SourceCfg)`)
- Modify: `src/likedbg/config.py` (remove `KernelDlCfg`, `KernelBuilderCfg`, legacy aliases now unused)
- Test: `src/tests/test_debuggee.py` (extend)

**Interfaces:**
- Produces: `build_qemu_argv(debuggee: DebuggeeCfg, host: HostProfile, *, target_arch: str, kernel_image: Path, rootfs: Path | None, extra_boot_args: tuple[str,...] = ()) -> list[str]`; `resolve_version(source: SourceCfg) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_debuggee.py  (add/replace the build_qemu_argv tests)
from pathlib import Path

from likedbg.config import DebuggeeCfg, Settings
from likedbg.host_profile import HostProfile, Probes
from likedbg.qemu import build_qemu_argv


def _host(machine="x86_64"):
    p = Probes(system=lambda: "linux", machine=lambda: machine, kvm_accessible=lambda: False,
               hvf_supported=lambda: False, native_qemu_present=lambda _a: True, workspace_case_sensitive=lambda _p: True)
    return HostProfile.detect(Settings(), Path("/tmp"), p)


def test_uses_effective_debuggee_and_extra_boot_args() -> None:
    eff = DebuggeeCfg(kaslr=False, memory_mib=2048)
    argv = build_qemu_argv(eff, _host(), target_arch="x86_64", kernel_image=Path("/k/bzImage"),
                           rootfs=None, extra_boot_args=("slub_debug=FZP",))
    append = argv[argv.index("-append") + 1]
    assert "nokaslr" in append and "slub_debug=FZP" in append
    assert "2048" in argv
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_debuggee.py -k effective -v`
Expected: FAIL (signature mismatch).

- [ ] **Step 3: Write minimal implementation**

Rewrite `qemu.py` to consume a `DebuggeeCfg` + `target_arch` (replace `settings.general.arch`/`settings.debuggee.*`):

```python
from likedbg.config import DebuggeeCfg


def _mitigations(d: DebuggeeCfg) -> list[str]:
    out = ["nokaslr" if not d.kaslr else "kaslr"]
    if not d.smep:
        out.append("nosmep")
    if not d.smap:
        out.append("nosmap")
    out.append("pti=on" if d.kpti else "nopti")
    return out


def _panic(d: DebuggeeCfg) -> str:
    return {"reboot": "panic=-1", "halt": "panic=0"}.get(d.panic, "panic=15")


def build_qemu_argv(debuggee: DebuggeeCfg, host: HostProfile, *, target_arch: str, kernel_image: Path,
                    rootfs: Path | None, extra_boot_args: tuple[str, ...] = ()) -> list[str]:
    argv = [_QEMU_BIN[target_arch]]
    if target_arch == "arm64":
        cpu = "host" if host.accel in ("hvf", "kvm") else "cortex-a72"
        argv += ["-M", "virt", "-cpu", cpu]
        console = "console=ttyAMA0"
    else:
        cpu = "qemu64"
        if debuggee.smep:
            cpu += ",+smep"
        if debuggee.smap:
            cpu += ",+smap"
        argv += ["-cpu", cpu]
        console = "console=ttyS0"
    argv += ["-accel", host.accel, "-m", str(debuggee.memory_mib), "-smp", str(debuggee.smp)]
    argv += ["-kernel", str(kernel_image)]
    drive_args, root = _rootfs_args(rootfs)
    append = " ".join([console, root, "earlyprintk=serial", "net.ifnames=0",
                       *_mitigations(debuggee), *extra_boot_args, "oops=panic", _panic(debuggee)])
    argv += ["-append", append, *drive_args, "-nographic"]
    if debuggee.gdb:
        argv += ["-S", "-gdb", f"tcp::{debuggee.gdb_port}"]
    return argv
```

In `download.py`: `from likedbg.config import SourceCfg`; rewrite `resolve_version`:

```python
def resolve_version(source: SourceCfg) -> str:
    if not source.value:
        raise DownloadError("no kernel source specified", remedy='set [source] value in configs/default.toml')
    return source.value
```

Update `DownloadStage._dest`/`run` to call `resolve_version(ctx.settings.source)`. Remove `KernelDlCfg`/`KernelBuilderCfg`/old aliases from `config.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_debuggee.py src/tests/test_kernel_downloader.py -v && uv run mypy src/likedbg/qemu.py src/likedbg/stages/download.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/qemu.py src/likedbg/stages/download.py src/likedbg/config.py src/tests/test_debuggee.py
git commit -m "feat(qemu): drive argv from effective_debuggee + target_arch + extra boot args; source kind/value"
```

---

## Task 15: `DebuggeeStage`/`DebuggerStage` read effective + record commands

**Files:**
- Modify: `src/likedbg/stages/debuggee.py`, `src/likedbg/stages/debugger.py`
- Test: `src/tests/test_debuggee.py`, `src/tests/test_debugger.py` (extend)

**Interfaces:**
- Consumes: `ctx.effective_debuggee` (fallback `ctx.settings.debuggee`), `ctx.host.target_arch`, `ctx.extra_boot_args`, `ctx.recorder`.
- Produces: launch status transitions via `ctx.recorder` (`launching`/`launched`/`launch-failed`); `record_command("qemu"/"gdb", ...)`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_debuggee.py  (add)
from likedbg.pipeline import PipelineContext


class _Rec:
    def __init__(self): self.statuses = []; self.cmds = []
    def set_status(self, s, *, message=None): self.statuses.append(s)
    def record_command(self, kind, *, shell, argv): self.cmds.append((kind, argv))
    def add_warning(self, *a, **k): pass


def test_debuggee_records_command_and_status(tmp_path):
    launched = {}
    stage = __import__("likedbg.stages.debuggee", fromlist=["DebuggeeStage"]).DebuggeeStage(
        launch=lambda cmd: launched.setdefault("cmd", cmd), debuggee_image="img")
    rec = _Rec()
    ctx = PipelineContext(settings=Settings(), host=_host(), build_label="b",
                          effective_debuggee=DebuggeeCfg(), kernel_image=Path("/k/bzImage"),
                          rootfs_image=None, recorder=rec)
    stage.run(ctx)
    assert ("qemu", ) == (rec.cmds[0][0],)
    assert "launching" in rec.statuses
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_debuggee.py -k records_command -v`
Expected: FAIL (status/command not recorded).

- [ ] **Step 3: Write minimal implementation**

`debuggee.py` `run`:

```python
    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.kernel_image is None:
            raise BuildError("no kernel image in context", remedy="run the Build/Export stages first")
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        argv = build_qemu_argv(eff, ctx.host, target_arch=ctx.host.target_arch,
                               kernel_image=ctx.kernel_image, rootfs=ctx.rootfs_image,
                               extra_boot_args=ctx.extra_boot_args)
        if ctx.host.debuggee_mode == "in-container":
            rw_mounts = [ctx.rootfs_image] if ctx.rootfs_image is not None else []
            cmd = qemu_container_command(argv, image=self._debuggee_image, ro_mounts=[ctx.kernel_image],
                                         rw_mounts=rw_mounts, gdbstub_port=eff.gdb_port,
                                         network_mode=ctx.host.network_mode, kvm=ctx.host.accel == "kvm")
        else:
            cmd = qemu_pane_command(argv)
        if ctx.recorder is not None:
            ctx.recorder.set_status("launching")          # type: ignore[attr-defined]
            ctx.recorder.record_command("qemu", shell=cmd, argv=argv)  # type: ignore[attr-defined]
        try:
            self._launch(cmd)
        except Exception:
            if ctx.recorder is not None:
                ctx.recorder.set_status("launch-failed", message="debuggee launch failed")  # type: ignore[attr-defined]
            raise
        return ctx
```

`debugger.py` `run`: read `ctx.host.target_arch` for `arch=`, `eff.gdb_port` for `port=`, record the gdb command, and set `launched` after `run_gdb` returns (the Debugger is the last pane). Use `getattr(ctx, "extra_boot_args", ())`-style guards only where a field may be absent — all are now defaulted on `PipelineContext`.

```python
    def run(self, ctx: PipelineContext) -> PipelineContext:
        if ctx.vmlinux is None:
            raise BuildError("no vmlinux in context", remedy="run the Build/Export stages first")
        eff = ctx.effective_debuggee or ctx.settings.debuggee
        args = build_gdb_args(ctx.host, arch=ctx.host.target_arch, vmlinux=ctx.vmlinux, ext=self._ext,
                              breakpoint=self._breakpoint, port=eff.gdb_port)
        if ctx.recorder is not None:
            ctx.recorder.record_command("gdb", shell=" ".join(args), argv=args)  # type: ignore[attr-defined]
        try:
            self._run_gdb(args)
        except Exception:
            if ctx.recorder is not None:
                ctx.recorder.set_status("launch-failed", message="debugger launch failed")  # type: ignore[attr-defined]
            raise
        if ctx.recorder is not None:
            ctx.recorder.set_status("launched")  # type: ignore[attr-defined]
        return ctx
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_debuggee.py src/tests/test_debugger.py -v && uv run mypy src/likedbg/stages/debuggee.py src/likedbg/stages/debugger.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/debuggee.py src/likedbg/stages/debugger.py src/tests/test_debuggee.py src/tests/test_debugger.py
git commit -m "feat(stages): read effective_debuggee/target_arch, record launch commands + status"
```

---

# Phase 8 — CLI Integration

## Task 16: CLI rewrite — flow reorder, profiles, recorder, transcript piping

**Files:**
- Modify: `src/likedbg/cli.py` (`main`, `build_pipeline`, `build_use_pipeline`, `cmd_use`)
- Test: `src/tests/test_start_kgdb.py` (rewrite for TOML + profiles + run dir)

**Interfaces:**
- Consumes: everything above. Default-run order: `load_config` → `HostProfile.detect` → `resolve_version` → `resolve_run` → `build_recipe(arch=host.target_arch, fragments=rr.fragments, patch_dirs=...)` → `RunRecorder.start` → `add_run_logfile(path=recorder.likedbg_log)` → `_ensure_images` → `pipeline.run`.
- New args: `--profile` (comma list), `--explain-config [text|json]` (Task 17 handles output; here just add the arg + early branch hook). `-c` becomes name-or-path → scenario file.
- Insert `ProfileVerificationStage(container, workspace, kernel_volume)` between `BuildStage` and `RootfsStage` in both pipelines. Thread `rr`, `rr.effective_debuggee`, `rr.extra_boot_args`, `recorder` onto `PipelineContext`. After `launch_debuggee` creates the pane, call `session.pipe_pane(pane=debuggee_pane, output=recorder.debuggee_pane_log)` and `session.set_option("@likedbg_debuggee_pane_log", str(recorder.debuggee_pane_log))`; after `run_gdb` creates the debugger pane, `session.pipe_pane(pane=debugger_pane, output=recorder.debugger_pane_log)`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_start_kgdb.py  (representative new cases; keep/adapt existing structure)
import json
from pathlib import Path

import pytest

from likedbg import cli
from likedbg.errors import ConfigError


def _project(tmp_path: Path) -> None:
    cfgs = tmp_path / "configs"
    (cfgs / "fragments" / "profiles").mkdir(parents=True)
    (cfgs / "profiles").mkdir(parents=True)
    (cfgs / "default.toml").write_text('[source]\nkind="mmp"\nvalue="6.6.30"\n')
    (cfgs / "fragments" / "generic.config").write_text("CONFIG_X=y\n")
    (cfgs / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\nfragments=["configs/fragments/generic.config"]\n')


def test_unknown_profile_no_run_dir(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TMUX", "1")
    with pytest.raises(ConfigError):
        cli.resolve_for_run(tmp_path, profile_arg="asan", scenario=None, cli_overrides=None)
    assert not (tmp_path / "artifacts" / "runs").exists()
```

(Refactor the resolution prelude into a small testable helper `cli.resolve_for_run(workspace, *, profile_arg, scenario, cli_overrides) -> tuple[ConfigResolution, HostProfile, RunResolution]` so the run-dir boundary is unit-testable without Docker/tmux. `main` calls it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_start_kgdb.py -k unknown_profile -v`
Expected: FAIL (`AttributeError: resolve_for_run`).

- [ ] **Step 3: Write minimal implementation**

Add the helper and rewire `main`. Key fragments (full edits in this file):

```python
def _scenario_path(workspace: Path, arg: str) -> Path | None:
    if not arg:
        return None
    p = Path(arg)
    if "/" in arg or arg.endswith(".toml"):
        return p
    return workspace / "configs" / "scenarios" / f"{arg}.toml"


def resolve_for_run(workspace: Path, *, profile_arg: str, scenario: Path | None,
                    cli_overrides: dict | None) -> tuple:
    from likedbg.config import load_config
    from likedbg.debug_profiles import parse_profile_names, resolve_run
    cfg = load_config(workspace, scenario=scenario, cli_overrides=cli_overrides)
    host = HostProfile.detect(cfg.settings, workspace)
    names = parse_profile_names(profile_arg) if profile_arg else cfg.settings.debugging.profiles
    rr = resolve_run(profile_names=names, config=cfg, host=host, workspace=workspace)
    for w in rr.profile_warnings:
        logger.warning(w)
    for n in (*rr.runtime_overrides, *rr.runtime_notes):
        logger.info(n)
    logger.info(f"resolved profiles: {', '.join(rr.profiles.names)}")
    return cfg, host, rr
```

Default-run block in `main` (replacing lines ~460-495): parse `--profile`/`--explain-config`; build `cli_overrides` from any `-c`/CLI flags (none beyond `-c` in B1 besides what existed); then:

```python
        scenario = _scenario_path(workspace, args.config)
        cfg, host, rr = resolve_for_run(workspace, profile_arg=args.profile, scenario=scenario, cli_overrides=None)
        version = resolve_version(cfg.settings.source)
        br = make_build_recipe(cfg.settings, version=version, arch=host.target_arch, workspace=workspace,
                               fragments=list(rr.fragments) + list(cfg.settings.build.extra_fragments),
                               patch_dirs=cfg.settings.build.patch_dirs)
        rr_recipe = make_rootfs_recipe(cfg.settings, arch=host.target_arch, workspace=workspace)
        if args.force_rebuild:
            cache.manifest_path(workspace, "build", br.label).unlink(missing_ok=True)
        if args.adopt:
            _require_volume_for_adopt(host)
            logger.info(f"adopted legacy build as {adopt_legacy_build(container, workspace=workspace, recipe=br)}")
            return 0
        if not os.getenv("TMUX"):
            logger.error("Not running inside a TMUX session. Start tmux first.")
            return 2
        recorder = RunRecorder.start(workspace=workspace, requested_settings=cfg.settings, run_resolution=rr,
                                     host=host, build_label=br.label, rootfs_label=rr_recipe.label,
                                     profiles=rr.profiles)
        logsetup.add_run_logfile(workspace, path=recorder.likedbg_log)
        _ensure_images(container, workspace, specs=images.required_for(host))
        chown_to = (os.getuid(), os.getgid()) if host.os == "linux" and host.storage_mode == "bind" else None
        session = Session("LIKE-DBG"); session.start("LIKE-DBG")
        ctx = PipelineContext(settings=cfg.settings, host=host, build_label=br.label, rootfs_label=rr_recipe.label,
                              run_resolution=rr, effective_debuggee=rr.effective_debuggee,
                              extra_boot_args=rr.extra_boot_args, recorder=recorder)
        pipeline = build_pipeline(container, session, host=host, chown_to=chown_to, workspace=workspace,
                                  kernel_volume=KERNEL_VOLUME, dl_dir=workspace / "kernels",
                                  debugger_image=DEBUGGER_IMAGE, debuggee_image=DEBUGGEE_IMAGE,
                                  ext=cfg.settings.debugger.ext, build_recipe=br, rootfs_recipe=rr_recipe,
                                  recorder=recorder)
        pipeline.run(ctx)
        return 0
```

`build_pipeline` (and `build_use_pipeline`): add a `recorder` param; insert `ProfileVerificationStage(container, workspace=workspace, kernel_volume=kernel_volume)` right after `BuildStage` (default) / as the first stage (use). In `launch_debuggee`, after creating the pane:

```python
        debuggee_pane = session.run_in_new_pane(target=base_pane, direction="h", percent=66, cmd=cmd)
        session.set_option("@likedbg_debuggee_pane", debuggee_pane)
        session.set_option("@likedbg_debuggee_pane_log", str(recorder.debuggee_pane_log))
        try:
            session.pipe_pane(pane=debuggee_pane, output=recorder.debuggee_pane_log)
        except LikeDbgError as exc:
            recorder.add_warning("transcript-capture-failed", f"pipe-pane failed for Debuggee: {exc}")
```

In `run_gdb`, after creating the debugger pane, the same `pipe_pane` to `recorder.debugger_pane_log` with the same warn-and-continue guard. `cmd_use` mirrors the default path but uses `--use` label and forces the manifest arch (load `cfg` then build `RunResolution` with `host` whose `target_arch` is overridden by the manifest arch — pass `cli_overrides={"general": {"arch": bm.arch}}` so `host.target_arch == bm.arch`).

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_start_kgdb.py -v && uv run mypy src/likedbg/cli.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cli.py src/tests/test_start_kgdb.py
git commit -m "feat(cli): TOML flow, --profile, RunRecorder wiring, verification stage, transcript piping"
```

---

## Task 17: `--explain-config [text|json]`

**Files:**
- Modify: `src/likedbg/cli.py` (early branch + renderer)
- Test: `src/tests/test_start_kgdb.py` (extend)

**Interfaces:**
- Produces: `explain_config(workspace, *, profile_arg, scenario, fmt: Literal["text","json"]) -> str`; branch in `main` before Docker client + tmux check; never creates a run dir.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_start_kgdb.py  (add)
def test_explain_config_json_no_run_dir(tmp_path, monkeypatch):
    _project(tmp_path)
    monkeypatch.chdir(tmp_path)
    out = cli.explain_config(tmp_path, profile_arg="", scenario=None, fmt="json")
    data = json.loads(out)
    assert data["profiles"]["resolved"] == ["exploit-dev"]
    assert data["target_arch"] in ("x86_64", "arm64")
    assert not (tmp_path / "artifacts" / "runs").exists()


def test_explain_config_marks_expectations_pending(tmp_path, monkeypatch):
    _project(tmp_path)
    (tmp_path / "configs" / "profiles" / "exploit-dev.toml").write_text(
        'name="exploit-dev"\nkind="base"\ndescription="d"\nfragments=["configs/fragments/generic.config"]\n'
        '[[expect]]\nsymbol="CONFIG_GDB_SCRIPTS"\nvalue="y"\nseverity="soft"\n')
    monkeypatch.chdir(tmp_path)
    data = json.loads(cli.explain_config(tmp_path, profile_arg="", scenario=None, fmt="json"))
    assert data["expected_config"][0]["status"] == "pending-build"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_start_kgdb.py -k explain_config -v`
Expected: FAIL (`AttributeError: explain_config`).

- [ ] **Step 3: Write minimal implementation**

```python
def explain_config(workspace: Path, *, profile_arg: str, scenario: Path | None, fmt: str) -> str:
    cfg, host, rr = resolve_for_run(workspace, profile_arg=profile_arg, scenario=scenario, cli_overrides=None)
    eff = rr.effective_debuggee
    payload = {
        "target_arch": rr.target_arch,
        "profiles": {"requested": list(rr.profiles.names), "base": rr.profiles.base,
                     "resolved": list(rr.profiles.names), "implied_by": {k: list(v) for k, v in rr.implied_by.items()}},
        "fragments": list(rr.fragments),
        "effective_debuggee": eff.model_dump(),
        "provenance": _provenance_nested(rr.provenance),
        "runtime_notes": list(rr.runtime_notes) + list(rr.runtime_overrides),
        "warnings": list(rr.profile_warnings),
        "extra_boot_args": list(rr.extra_boot_args),
        "expected_config": [
            {"symbol": e.symbol, "value": e.value, "severity": e.severity,
             "arch": list(e.arch) if e.arch else None, "kernel_min": e.kernel_min, "kernel_max": e.kernel_max,
             "status": "pending-build"} for e in rr.profiles.expected_config
        ],
    }
    if fmt == "json":
        return json.dumps({"schema_version": 1, **payload}, indent=2, sort_keys=True)
    lines = [f"target arch: {payload['target_arch']}",
             f"profiles:    {', '.join(payload['profiles']['resolved'])} (base {payload['profiles']['base']})",
             "fragments:", *[f"  {f}" for f in payload["fragments"]],
             "warnings:", *[f"  {w}" for w in payload["warnings"]] or ["  (none)"],
             "expected config (pending build):",
             *[f"  {e['symbol']}={e['value']} [{e['severity']}]" for e in payload["expected_config"]]]
    return "\n".join(lines)


def _provenance_nested(prov: dict) -> dict:
    out: dict = {}
    for (section, key), layer in prov.items():
        out.setdefault(section, {})[key] = layer
    return out
```

Add args: `parser.add_argument("--profile", default="")` and `parser.add_argument("--explain-config", nargs="?", const="text", default=None, choices=["text", "json"])`. Early in `main` (right after `configure_stderr`, before any Docker client):

```python
        if args.explain_config is not None:
            print(explain_config(workspace, profile_arg=args.profile,
                                 scenario=_scenario_path(workspace, args.config), fmt=args.explain_config))
            return 0
```

(`workspace = Path.cwd()` must be computed before this branch.)

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_start_kgdb.py -k explain_config -v && uv run mypy src/likedbg/cli.py`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cli.py src/tests/test_start_kgdb.py
git commit -m "feat(cli): --explain-config [text|json] dry-run renderer (Docker/tmux-less)"
```

---

# Phase 9 — Config Files, Profiles, Fragments, Migration

## Task 18: Built-in config + profile + fragment files; remove INI

**Files:**
- Create: `configs/default.toml`, `configs/local.example.toml`, `configs/scenarios/.gitkeep`, `configs/profiles/{exploit-dev,hardened,crash-debug,kasan,ubsan,lockdep,kcov-lite}.toml`, `configs/fragments/profiles/{exploit-dev,hardened,crash-debug,kasan,ubsan,lockdep,kcov-lite}.config`
- Modify: `.gitignore` (add `configs/local.toml`)
- Delete: `configs/system.ini`, `configs/user.ini`
- Test: `src/tests/test_builtin_profiles.py` (loads the real registry + a real default run resolution)

**Interfaces:** the shipped registry must resolve and pass schema validation; `exploit-dev` reuses existing `configs/fragments/{generic,debug,no-kaslr}.config`.

- [ ] **Step 1: Write the failing test**

```python
# src/tests/test_builtin_profiles.py
from pathlib import Path

from likedbg.config import load_config
from likedbg.debug_profiles import load_profiles, resolve_run
from likedbg.host_profile import HostProfile, Probes

REPO = Path(__file__).resolve().parents[2]


def _host():
    p = Probes(system=lambda: "linux", machine=lambda: "x86_64", kvm_accessible=lambda: False,
               hvf_supported=lambda: False, native_qemu_present=lambda _a: True, workspace_case_sensitive=lambda _p: True)
    return HostProfile.detect(load_config(REPO).settings, REPO, p)


def test_registry_loads_and_names_match() -> None:
    reg = load_profiles(REPO)
    assert {"exploit-dev", "hardened", "crash-debug", "kasan", "ubsan", "lockdep", "kcov-lite"} <= set(reg)
    assert reg["exploit-dev"].kind == "base" and reg["hardened"].kind == "base"


def test_default_run_resolves_exploit_dev_with_existing_fragments() -> None:
    cfg = load_config(REPO)
    rr = resolve_run(profile_names=("exploit-dev",), config=cfg, host=_host(), workspace=REPO)
    assert rr.profiles.base == "exploit-dev"
    for frag in rr.fragments:
        assert (REPO / frag).is_file()


def test_kasan_resolution_orders_and_implies() -> None:
    cfg = load_config(REPO)
    rr = resolve_run(profile_names=("kasan",), config=cfg, host=_host(), workspace=REPO)
    assert rr.profiles.names[:2] == ("exploit-dev", "crash-debug")
    assert "kasan" in rr.profiles.names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest src/tests/test_builtin_profiles.py -v`
Expected: FAIL (no `configs/default.toml`/`configs/profiles/*`).

- [ ] **Step 3: Write minimal implementation**

`configs/default.toml` (the working project defaults, preserving today's behavior):

```toml
[general]
arch = "native"
mac_storage = "auto"

[source]
kind = "mmp"
value = "6.6.30"

[build]
compiler = "clang"
toolchain = "auto"
rust = false

[rootfs]
distribution = "bookworm"
hostname = "LIKE-DBG"

[debuggee]
memory_mib = 1024
smp = 1
accel = "auto"
network = "auto"
gdb = true
gdb_port = 1234
kaslr = false
smep = true
smap = true
kpti = true
panic = "halt"

[debugger]
ext = "pwndbg"

[debugging]
profiles = ["exploit-dev"]
```

`configs/local.example.toml`:

```toml
# Copy to configs/local.toml (gitignored) for personal overrides.
[general]
# arch = "x86_64"   # pin a cross-arch target; default "native" follows the host

[source]
# kind = "tag"
# value = "v6.9"

[debugger]
# ext = "gef"        # pwndbg is the default; opt into gef here
```

`configs/profiles/exploit-dev.toml` (reuses existing fragments):

```toml
name = "exploit-dev"
kind = "base"
description = "Convenient exploit research baseline: predictable addresses, source-aware GDB."
fragments = [
  "configs/fragments/generic.config",
  "configs/fragments/debug.config",
  "configs/fragments/no-kaslr.config",
]

[[expect]]
symbol = "CONFIG_DEBUG_INFO"
value = "y"
severity = "soft"

[[expect]]
symbol = "CONFIG_GDB_SCRIPTS"
value = "y"
severity = "soft"

[[expect]]
symbol = "CONFIG_RANDOMIZE_BASE"
value = "n"
severity = "hard"
```

`configs/profiles/hardened.toml`:

```toml
name = "hardened"
kind = "base"
description = "Exploit workbench with mitigations compiled in (KASLR/SMEP/SMAP/KPTI showcasable)."
fragments = [
  "configs/fragments/generic.config",
  "configs/fragments/debug.config",
  "configs/fragments/profiles/hardened.config",
]

[runtime_defaults.debuggee]
kaslr = true
smep = true
smap = true
kpti = true

[[expect]]
symbol = "CONFIG_RANDOMIZE_BASE"
value = "y"
severity = "hard"
arch = ["x86_64", "arm64"]
```

`configs/profiles/crash-debug.toml`:

```toml
name = "crash-debug"
kind = "addon"
description = "Readable oops/panic triage while preserving a normal-ish kernel."
fragments = ["configs/fragments/profiles/crash-debug.config"]

[[expect]]
symbol = "CONFIG_DEBUG_INFO"
value = "y"
severity = "soft"
```

`configs/profiles/kasan.toml`:

```toml
name = "kasan"
kind = "addon"
description = "Memory bug detection for UAF/OOB research."
implies = ["crash-debug"]
fragments = ["configs/fragments/profiles/kasan.config"]

[[warning]]
message = "KASAN under TCG is slow and memory-heavy."
accel = ["tcg"]

[[warning]]
message = "KASAN + lockdep is slow and noisy."
profiles = ["lockdep"]

[[expect]]
symbol = "CONFIG_KASAN"
value = "y"
severity = "hard"
arch = ["x86_64", "arm64"]
kernel_min = "5.10"
```

`configs/profiles/ubsan.toml`:

```toml
name = "ubsan"
kind = "addon"
description = "Lower-cost undefined-behavior detection."
implies = ["crash-debug"]
fragments = ["configs/fragments/profiles/ubsan.config"]

[[expect]]
symbol = "CONFIG_UBSAN"
value = "y"
severity = "hard"
```

`configs/profiles/lockdep.toml`:

```toml
name = "lockdep"
kind = "addon"
description = "Locking and concurrency diagnostics."
fragments = ["configs/fragments/profiles/lockdep.config"]

[[warning]]
message = "lockdep can be noisy and slows the kernel."

[[expect]]
symbol = "CONFIG_PROVE_LOCKING"
value = "y"
severity = "soft"
```

`configs/profiles/kcov-lite.toml`:

```toml
name = "kcov-lite"
kind = "addon"
description = "Prepare kernels for later coverage-guided bug finding (not a fuzzing workflow itself)."
fragments = ["configs/fragments/profiles/kcov-lite.config"]

[[warning]]
message = "kcov-lite enables coverage prerequisites but is not a fuzzer by itself."

[[expect]]
symbol = "CONFIG_KCOV"
value = "y"
severity = "soft"
```

Fragments under `configs/fragments/profiles/` (conservative, schema-satisfying content):

```text
# hardened.config
CONFIG_RANDOMIZE_BASE=y
CONFIG_RANDOMIZE_MEMORY=y
```
```text
# crash-debug.config
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_PANIC_ON_OOPS=y
CONFIG_DEBUG_BUGVERBOSE=y
CONFIG_MAGIC_SYSRQ=y
```
```text
# kasan.config
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
```
```text
# ubsan.config
CONFIG_UBSAN=y
CONFIG_UBSAN_BOUNDS=y
```
```text
# lockdep.config
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_LOCK_ALLOC=y
CONFIG_LOCKDEP=y
```
```text
# kcov-lite.config
CONFIG_KCOV=y
CONFIG_DEBUG_FS=y
```

Add `configs/local.toml` to `.gitignore`; `git rm configs/system.ini configs/user.ini`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest src/tests/test_builtin_profiles.py -v && uv run pytest`
Expected: PASS; the **full** suite now green (any remaining INI-based tests must have been migrated/removed in earlier tasks — fix stragglers here).

- [ ] **Step 5: Commit**

```bash
git add configs .gitignore && git rm configs/system.ini configs/user.ini
git add src/tests/test_builtin_profiles.py
git commit -m "feat(configs): ship default.toml + profile registry + profile fragments; drop INI"
```

---

# Phase 10 — Documentation

## Task 19: ADR-0006, CONTEXT.md, ROADMAP, README

**Files:**
- Modify: `docs/adr/0006-toml-configuration-and-debug-profiles.md`, `CONTEXT.md`, `docs/superpowers/ROADMAP.md`, `README.md`
- Test: none (docs) — but run `uv run pytest` to confirm nothing regressed.

- [ ] **Step 1: ADR-0006 amendments**

Append a "Resolution (2026-06-26 grill)" section recording: whole-Settings provenance via `load_config`→`ConfigResolution`; `native` resolved in `HostProfile.detect` (`target_arch`); profile runtime defaults at layer 4 → `effective_debuggee`; `pwndbg` is the de facto default, `gef` via local override; two-phase load; `-c` name-or-path; `custom_modules` deferred to B6.

- [ ] **Step 2: CONTEXT.md glossary** — add three terms (use the file's existing term style):

```text
**Effective settings**:
The runtime Debuggee toggles LIKE-DBG actually uses after the 6-layer precedence merge — built-in <
project default < profile runtime defaults < local < scenario < CLI. Held as
`RunResolution.effective_debuggee`; QEMU/GDB read it, never the frozen requested `Settings`.
_Avoid_: mutating `Settings`; calling profile defaults "overrides" (they are the lowest non-default layer).

**Configuration provenance**:
The winning layer recorded per `(section, key)` by the TOML loader, surfaced in
`settings.effective.json`/`--explain-config`. Internal/debuggable state — users see only three layers
(project defaults, local/scenario, CLI). _Avoid_: exposing all six layers in everyday UX.
```

(Also extend the existing **Run artifact** term to name the status set `created → profile-verification-failed | launching → launched | launch-failed`.)

- [ ] **Step 3: ROADMAP.md** — under §D, mark B1+B2 as *spec'd + grilled + planned (2026-06-26)*, point at this plan, and note the §10 grill decisions. Move the "Status" date forward.

- [ ] **Step 4: README** — document `--profile`, `--explain-config`, the `configs/*.toml` stack (default/local/scenario, `pwndbg` default), `artifacts/runs/<run-id>/`, the not-byte-perfect transcript caveat (incl. the per-restart gap).

- [ ] **Step 5: Commit**

```bash
git add docs/adr/0006-toml-configuration-and-debug-profiles.md CONTEXT.md docs/superpowers/ROADMAP.md README.md
git commit -m "docs: record B1/B2 grill decisions in ADR-0006, glossary, roadmap, README"
```

---

# Phase 11 — Live Gates (manual; controller-driven)

## Task 20: Live verification checklist

**Files:** none (operational). Record outcomes in `docs/superpowers/notes/2026-06-26-b1-b2-live.md`.

- [ ] **Gate 1 — default arm64 on the M5 (volume mode):** `tmux -L likedbg -f .tmux.conf new -s LIKE-DBG`, then `uv run ./start_kgdb`. Verify: build/reuse, boot, pwndbg attaches at `start_kernel`; `artifacts/runs/<id>/` exists with all JSONs + `commands/` + `logs/`; `debuggee-pane.log`/`debugger-pane.log` receive output; `profile-verification` passes; `artifacts/runs/latest` resolves. Then `C-b B` restart → `likedbg-reconnect` → confirm `debuggee-pane.log` keeps growing (restart re-pipe).
- [ ] **Gate 2 — x86_64-on-Mac `--use` (in-container TCG):** run dir exists, transcripts captured, verification runs before boot.
- [ ] **Gate 3 — `--explain-config` / failure evidence:** `uv run ./start_kgdb --explain-config json` outside tmux prints stable JSON, creates no run dir. Force a `--use old-build --profile hardened` mismatch → run dir with `status="profile-verification-failed"` + `profiles.json`.
- [ ] **Gate 4 (optional, expensive):** one `uv run ./start_kgdb --profile kasan` build on the fastest arch; confirm `CONFIG_KASAN=y` verified. If too slow for routine use, document as manual-only.
- [ ] **Commit notes:** `git add docs/superpowers/notes/2026-06-26-b1-b2-live.md && git commit -m "docs: B1/B2 live-gate transcript"`.

---

## Self-Review (run before handing off to execution)

**Spec coverage** (each §/decision → task):
- §5.1 TOML schema, CLI `--profile`/`--explain-config`, `extra_fragments`, `patch_dirs`, `input_hash` → Tasks 1,2,3,8,16,17,18. `custom_modules` deferred to B6 (Q4) → schema slot only, Task 2.
- §5.2 initial profiles → Task 18. §5.3 module interface/`resolve_run`/`verify_config` → Tasks 5,6,7. §5.4 compatibility + provenance + `native` → Tasks 3,4,7. §5.5 settings/cache identity → Tasks 2,3,8. §5.6 pipeline integration + verification stage (bind/volume read, cache hit) → Tasks 9,10,11,16. §5.7 boot args → Task 7 (resolve) + 14 (QEMU).
- §6.1 run layout/status → Task 12. §6.2 RunRecorder → Task 12. §6.3 log setup → Task 12. §6.4 transcript + restart → Task 13,16. §6.5 command recording → Task 15. §6.6 kernel path recording → Tasks 11,12.
- §7 errors → Tasks 7,11,16. §8 testing → tests in each task; live gates Task 20. §9 DoD → Tasks 16,18,19 + Gate checklist.
- §10 grill decisions 1–12 → all baked in (1:T7, 2:T3, 3:T4, 4:T2/T8, 5:T9/T10/T11, 6:T2/T5, 7:T13, 8:T12/T16, 9:T3/T18, 10:T14, 11:T17, 12:T7/T11).

**Placeholder scan:** no "TBD"/"add error handling"/"similar to Task N" — each step carries real code. (Task 9 notes a one-time backfill path and Task 16 references full edits in-file; both specify the exact code/behavior.)

**Type consistency:** `RunResolution.effective_debuggee: DebuggeeCfg`, `resolve_run(*, profile_names, config, host, workspace)`, `build_recipe(..., arch=, fragments=, patch_dirs=)`, `build_qemu_argv(debuggee, host, *, target_arch, kernel_image, rootfs, extra_boot_args)`, `RunRecorder.start(*, workspace, requested_settings, run_resolution, host, build_label, rootfs_label, profiles)`, `Session.pipe_pane(*, pane, output)` — used identically across producing/consuming tasks.

**Known cross-task coupling to watch during execution:** `rootfs_recipe` gains an `arch=` param (Task 8 note) consumed in Task 16 (`make_rootfs_recipe(..., arch=host.target_arch)`); `PipelineContext` field additions (Task 10) are relied on by Tasks 9, 11, 15, 16.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-26-modern-debugging-ux-b1-b2-plan.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks, fast iteration. Matches the ROADMAP workflow (implementer=haiku when the task carries full code / sonnet for CLI/integration tasks 16–17; review=sonnet; final whole-branch review=opus).
2. **Inline Execution** — execute tasks in this session via `superpowers:executing-plans`, batched with checkpoints.

Which approach?

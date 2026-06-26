# Modern Debugging UX B1+B2 - Debug Profiles & Run Artifacts

- **Date:** 2026-06-25
- **Status:** draft design after brainstorm; ready for grill + implementation plan
- **Scope:** Sub-project B, slices B1 and B2 only
- **ADR:** `docs/adr/0006-toml-configuration-and-debug-profiles.md`

## 1. Context

Foundation is complete. The current `dev` branch can build/reuse a Kernel Build and rootfs,
boot arm64 and x86_64 across macOS/Linux, attach GEF or pwndbg, restart the Debuggee process pane,
and reconnect GDB with `likedbg-reconnect`. The next upgrade should make the live kernel debugging
session feel like an exploit-development workbench rather than only a QEMU/GDB launcher.

The full Sub-project B roadmap slice is:

1. **B1:** debug profiles + post-build `.config` verification.
2. **B2:** per-run artifacts + QEMU/GDB pane transcript capture.
3. **B3:** crash/oops detector + symbolized reports.
4. **B4:** LIKE-DBG GDB helper pack + breakpoint profiles.
5. **B5:** reset/snapshot controls.
6. **B6:** guest exploit deploy/run loop.

This spec implements only B1 and B2. B3-B6 are recorded here only where their future needs shape
the B1/B2 interfaces.

## 2. Goals

- Add named debug profiles that work across macOS/Linux, x86_64/arm64, native-host QEMU, in-container
  QEMU, GEF, and pwndbg.
- Preserve the current default behavior at the user-experience level while making it explicit: the default run
  should be equivalent to an `exploit-dev` profile that includes the existing generic/debug/no-KASLR intent.
  B1 fully converts runtime configuration to TOML and replaces the old `system.ini`/`user.ini` layering with
  a clearer modular stack with provenance. There is no legacy INI fallback.
- Verify the final built `.config` after both fresh builds and cache hits, because kconfig silently drops
  options when dependencies are unmet.
- Create a durable run directory for every interactive run with enough metadata to reproduce, inspect,
  or feed later crash analysis and AI assistance.
- Capture Debuggee and Debugger pane transcripts without changing the interactive tmux workflow.
- Keep the public interfaces small: profile resolution and run recording should be deep modules, not logic
  spread across `cli.py`, stages, and launchers.

## 3. Non-Goals

- No crash/oops parsing yet. B2 captures logs; B3 interprets them.
- No symbolized panic report yet. B3 owns `crash.json` and `crash.md`.
- No new GDB helper commands except any minimal plumbing needed to record command metadata. B4 owns the
  helper pack.
- No QMP/HMP reset or savevm/loadvm controls. B5 owns those.
- No guest exploit copy/build/run commands. B6 owns those.
- No syzkaller integration. Sub-project D owns that after B has sanitizer and crash artifact foundations.
- No cache/adoption event audit tree. A future cache-management slice may add `artifacts/events/` for
  operations such as `--adopt`, `--adopt-rootfs`, `--clean`, and image rebuilds.
- No full custom base `.config` support. B1 removes `build.mode` and uses profile/custom fragments layered
  on architecture defconfig. A future slice may add a deliberate `build.base_config` design if needed.

## 4. Design Principles

- **Profile resolution is the build-time seam.** Callers ask one module for the resolved profile set and
  receive fragments, expected config assertions, boot args, and warnings. They do not know individual
  profile internals.
- **Build-time contradictions are errors.** If a Debug profile changes what the Kernel Build supports, a
  runtime setting that asks for impossible behavior must hard-error during profile/config resolution.
  Runtime settings that merely override supported behavior should warn or note the override and continue.
- **Run recording is the runtime seam.** Callers ask one module for paths and record events/commands through
  a small interface. They do not assemble artifact paths by hand.
- **Verification beats assumptions.** A profile requesting `CONFIG_KASAN=y` is not successful until the
  produced `.config` contains the expected value.
- **Artifacts are append-only operator evidence.** They should capture what happened, not become hidden
  mutable state that controls later runs.
- **Portability first.** Prefer kconfig fragments, boot args, tmux pane piping, JSON/Markdown, and Python.
  Avoid host-specific helper tools outside containers.
- **TOML all the way for configuration.** B1 should not introduce a mixed TOML/INI future. Profile
  definitions and the modernized runtime configuration stack use TOML. Legacy INI config files are migrated,
  not supported as fallbacks.
- **Configuration layers must earn their keep.** Provenance is valuable, but six layers must not become six
  concepts the user has to juggle on every run. Keep the everyday UX to project defaults, optional local
  overrides, optional scenario config, and CLI. Built-in defaults and profile defaults are mostly internal
  provenance layers surfaced only when explaining effective settings.

## 5. B1: Debug Profiles

### 5.1 User Interface

Add or migrate to a TOML debug-profile config section:

```toml
[debugging]
profiles = ["exploit-dev"]
```

Modern runtime TOML schema:

```toml
[general]
arch = "native"
workspace_dir = ""
mac_storage = "auto"

[source]
kind = "mmp" # mmp | tag | commit
value = "6.6.30"

[build]
compiler = "clang"
toolchain = "auto"
rust = false
label_suffix = ""
patch_dirs = []
custom_modules = []
extra_fragments = []

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

The TOML schema may clean up old INI section/key names. In particular, `kernel_dl` becomes `source`,
`kernel_builder` becomes `build`, `memory` becomes `memory_mib`, booleans become real TOML booleans, and
`profiles` is a real TOML list. Source selection uses explicit `kind`/`value` instead of precedence among
`mmp`, `tag`, and `commit`. The old `general.kernel_tag` becomes `build.label_suffix` to avoid confusion
with Git/source tags.
The old `build.mode = generic|syzkaller|custom|config` is removed. Kernel configuration intent now lives in
Debug profiles and kconfig fragments. The build starts from the architecture defconfig, applies resolved
profile/custom fragments in deterministic order, then runs `olddefconfig`.
Full custom base `.config` support is out of B1; custom profile fragments are the extension path.
`build.extra_fragments` is the lightweight one-off escape hatch. Extra fragments follow the same path
restrictions as profile fragments, apply after resolved profile fragments, are included in BuildRecipe cache
inputs, are copied into Run artifacts, and are recorded separately from profile-owned fragments.
Extra fragments do not define profile verification expectations directly. They affect the final `.config`,
but expectations come from Debug profile TOML files; users who need new expectations should create a custom
profile.
`build.patch_dirs` and `build.custom_modules` stay in B1 because patching kernels and building custom kernel
modules are mandatory exploit-development workflows. Both are lists of relative workspace paths. Reject
absolute paths and `..` traversal. When either
is set, its relevant content must participate in BuildRecipe cache identity so changing a patch or module
source cannot silently reuse a stale Kernel Build. Run artifacts should record the configured paths and a
content hash summary, not copy large source trees.
Patch directories apply in TOML list order; patch files inside each directory apply in sorted filename order.
Custom modules build in TOML list order. Cache identity records each configured path and tree hash in that
same order.
Hash these directories recursively by sorted relative path and file content. Ignore explicit build junk such
as `.git/`, `__pycache__/`, `.DS_Store`, `*.o`, `*.ko`, `*.mod`, `*.mod.c`, `Module.symvers`,
`modules.order`, and `.tmp_versions/`. Prefer a small documented ignore list over extension allow-lists.

Add `src/likedbg/input_hash.py` as the shared hashing module for this behavior:

```python
def hash_file(path: Path) -> str: ...
def hash_tree(root: Path, *, ignore: IgnoreRules = DEFAULT_IGNORE) -> TreeHash: ...
```

`TreeHash` contains the aggregate SHA-256 and the sorted per-file hash records used for manifests and Run
artifact summaries. `BuildRecipe` uses this helper for each `patch_dirs` and `custom_modules` entry; `RunRecorder` uses
the same values when writing input summaries. Future slices can reuse it for exploit payload directories or
other workspace inputs.

Add CLI support:

```sh
uv run ./start_kgdb --profile kasan
uv run ./start_kgdb --profile exploit-dev,ubsan
uv run ./start_kgdb --explain-config
uv run ./start_kgdb --explain-config json
```

CLI `--profile` is a single comma-separated list and overrides the TOML `debugging.profiles` list for that
invocation; it does not append to it. Repeated `--profile` flags are not supported in B1. This keeps a TOML
config-file UX while allowing quick experiments from the shell. The exact config file names may change as part of the
provenance-aware configuration cleanup; profile semantics do not depend on the old `system.ini`/`user.ini`
split, which is removed rather than preserved.
`--profile` must contain at least one non-empty profile name; an empty string is a `ConfigError`.
If `debugging.profiles` is absent from TOML, it defaults to `["exploit-dev"]`. If it is present as an empty
list, that is a `ConfigError`.
`--explain-config` is a non-interactive B1 inspection path that resolves TOML layers, profiles, profile
runtime defaults, user overrides, and `native` target arch without building or booting. It does not create a
Run artifact. It takes an optional fixed output format argument: `--explain-config [text|json]`, defaulting
to `text`.

The default is `exploit-dev`, preserving today's implicit fragment set:

- `configs/fragments/generic.config`
- `configs/fragments/debug.config`
- `configs/fragments/no-kaslr.config`

`hardened` is an explicit opt-in profile for mitigation bypass demos and research. It must not be part of
the default profile chain.

### 5.2 Initial Profiles

Profiles are composable by default, but they have categories:

- **Base profiles:** choose the core exploit/debugging intent. Exactly one base profile may be active.
  Initial base profiles are `exploit-dev` and `hardened`.
- **Add-on profiles:** add capabilities to the selected base profile. Initial add-ons are `crash-debug`,
  `kasan`, `ubsan`, `lockdep`, and `kcov-lite`.

`exploit-dev` and `hardened` are mutually exclusive because they make conflicting build-time KASLR decisions.
`crash-debug` is an add-on; it may be used with either base profile, and other add-on profiles may imply it
where that avoids duplicating fragment lists.
Base profiles do not imply `crash-debug`; requesting `exploit-dev` or `hardened` alone keeps the base profile
lightweight. Sanitizer-style add-ons may imply `crash-debug` because they are crash-analysis workflows.

Profile authoring must stay clean and enjoyable as the list grows. Adding a new add-on profile should mean
adding a small TOML profile definition and one or more fragments, not editing scattered Python conditionals
or copying long fragment lists.

Profile definitions live under:

```text
configs/profiles/
  exploit-dev.toml
  hardened.toml
  crash-debug.toml
  kasan.toml
  ubsan.toml
  lockdep.toml
  kcov-lite.toml
```

Users may add custom profiles by placing additional TOML files in `configs/profiles/`. B1 does not support
custom profile search paths or `--profile-dir`; the standard project directory is the only profile registry.
Custom profile files use the same schema, resolver, validation, and fragment-ordering rules as built-ins.
Profile filenames and names must match: `configs/profiles/my-uaf.toml` must contain `name = "my-uaf"`.
Duplicate profile names are hard errors. Profile names must match `[a-z0-9][a-z0-9._-]*`.
Profile names are case-sensitive and lowercase; uppercase CLI/config names are rejected rather than
normalized.

Profile-owned fragments live under:

```text
configs/fragments/profiles/
  exploit-dev.config
  hardened.config
  crash-debug.config
  kasan.config
  ubsan.config
  lockdep.config
  kcov-lite.config
```

B1 creates the built-in TOML registry and the initial fragments needed by those built-in profiles. Existing
fragments such as `configs/fragments/generic.config`, `debug.config`, and `no-kaslr.config` may be reused
where they already express the intended behavior; new files under `configs/fragments/profiles/` should be
added where a profile needs dedicated config.
B1 ships all initial built-in profiles: `exploit-dev`, `hardened`, `crash-debug`, `kasan`, `ubsan`,
`lockdep`, and `kcov-lite`. Use conservative hard/soft expectations and arch/kernel selectors where live
validation is incomplete, but the profile vocabulary and files land together.

Profile fragment paths must be relative paths under `configs/fragments/`. The resolver rejects absolute
paths, `..` traversal, and files outside `configs/fragments/`. Custom profiles may use
`configs/fragments/profiles/` or another subdirectory under `configs/fragments/`, but not arbitrary
workspace files.

`debug_profiles.py` is still the deep module: it loads these declarative files, expands implications,
validates base/add-on rules, orders fragments, checks runtime compatibility, and verifies `.config`.
TOML defines facts; Python owns compatibility logic. Do not turn profile files into a rules language.

Example profile definition:

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

**`exploit-dev`**

- Purpose: convenient exploit research baseline.
- Fragments: generic kernel usability, debug symbols, frame pointers, GDB scripts, kallsyms, no KASLR.
- Runtime intent: predictable addresses, source-aware GDB, readable symbols.
- Expected config examples: `CONFIG_DEBUG_INFO=y`, `CONFIG_FRAME_POINTER=y`, `CONFIG_GDB_SCRIPTS=y`,
  `CONFIG_KALLSYMS=y`, `CONFIG_KALLSYMS_ALL=y`, `CONFIG_RANDOMIZE_BASE` not set.

**`hardened`**

- Purpose: build an exploit-workbench kernel with exploit-relevant mitigations compiled in, so the operator
  can demonstrate bypassing KASLR/SMEP/SMAP/KPTI or selectively disabling them at runtime without rebuilding.
- Default status: explicit opt-in, not included in the default `exploit-dev` profile.
- Meaning: an exploit workbench with mitigations compiled in, not a production distro config.
- Fragments: generic kernel usability, debug symbols, frame pointers, GDB scripts, kallsyms, and typical
  exploit-relevant hardening/mitigation support compiled in, including KASLR support where available.
- Runtime intent: `[debuggee] kaslr/smep/smap/kpti` stay meaningful toggles because the kernel was built
  with support for the mitigations being showcased. Runtime config may turn supported mitigations on or off
  without rebuilding.
- Runtime defaults: `hardened` contributes effective runtime defaults that turn typical mitigations on
  (`kaslr`, `smep`, `smap`, `kpti`) unless the user explicitly overrides them in config or CLI.
- Expected config examples: debug info, frame pointers, kallsyms, and `CONFIG_RANDOMIZE_BASE=y` on supported
  architectures.
- Conflict: incompatible with `exploit-dev` because `exploit-dev` intentionally disables
  `CONFIG_RANDOMIZE_BASE`.

**`crash-debug`**

- Purpose: readable oops/panic triage while preserving a normal-ish kernel.
- Fragments: generic + debug info + verbose BUG/oops/debug settings + sysrq where available.
- Runtime intent: keep serial logs useful and make stack traces easier to symbolize.
- Expected config examples: debug info, frame pointers, kallsyms, verbose BUG support where available.

**`kasan`**

- Purpose: memory bug detection for exploit development and later fuzzing.
- Fragments: crash-debug plus KASAN generic settings.
- Implies: `crash-debug`.
- Runtime intent: high-signal reports for UAF/OOB classes.
- Warnings: slow under TCG, memory-heavy, and some options may be unavailable by architecture/version.
- Expected config examples: `CONFIG_KASAN=y` and a supported mode such as generic KASAN.

**`ubsan`**

- Purpose: lower-cost undefined-behavior detection.
- Fragments: crash-debug plus UBSAN settings.
- Implies: `crash-debug`.
- Expected config examples: `CONFIG_UBSAN=y`.

**`lockdep`**

- Purpose: locking and concurrency diagnostics.
- Fragments: lockdep/prove-locking settings where supported.
- Warnings: can be noisy and slower.

**`kcov-lite`**

- Purpose: prepare kernels for later coverage-guided bug finding without implementing syzkaller yet.
- Fragments: KCOV and debugfs prerequisites where supported.
- Warnings: not a fuzzing workflow by itself.

### 5.3 Profile Module Interface

Add `src/likedbg/debug_profiles.py`.

Primary public interface:

```python
def resolve_run(*, profile_names: list[str], settings: Settings, workspace: Path) -> RunResolution
```

`RunResolution` contains:

- `requested_settings: Settings`
- `provenance: dict[tuple[str, str], str]`
- `target_arch: Literal["x86_64", "arm64"]`
- `profiles: ResolvedDebugProfiles`
- `fragments: tuple[str, ...]`
- `runtime_defaults: dict[str, str]`
- `runtime_overrides: tuple[str, ...]`
- `extra_boot_args: tuple[str, ...]`
- `profile_warnings: tuple[str, ...]`
- `runtime_notes: tuple[str, ...]`

`ResolvedDebugProfiles` contains:

- `names: tuple[str, ...]`
- `base: str`
- `expected_config: tuple[ConfigExpectation, ...]`
- `future_breakpoint_groups: tuple[str, ...]`

`ConfigExpectation` supports at least:

- `CONFIG_FOO=y`
- `CONFIG_FOO=m`
- `CONFIG_FOO is not set`
- optional selectors: `arch`, `kernel_min`, and `kernel_max`.

Built-in profiles should mark core requested capabilities as `hard`. If a user asks for `kasan`, `ubsan`,
`lockdep`, or `kcov-lite`, the corresponding core capability flags must be present in the final `.config`
or the run fails before boot. Secondary helpers that improve ergonomics but are not the named capability may
use `soft` expectations and warn instead.

Secondary public interface:

```python
def verify_config(config_text: str, resolved: ResolvedDebugProfiles) -> ProfileVerification
```

`ProfileVerification` reports:

- satisfied expectations
- missing hard expectations
- missing soft expectations
- human-facing warning lines

This keeps kconfig knowledge inside one module. The CLI and stages do not inspect profile internals.
`RunResolution` lives in `debug_profiles.py` for B1/B2; if later slices need a broader run model, it can be
promoted then.

Profile definition file schema:

- `name: str`
- `kind: "base" | "addon"`
- `description: str`
- `implies: list[str]`
- `fragments: list[str]`
- `boot_arg: list[{ value, arch?, kernel_min?, kernel_max?, profiles? }]`
- `runtime_defaults: dict[str, str]`
- `warning: list[{ message, arch?, accel?, host_os?, profiles? }]`
- `expect: list[{ symbol, value, severity, arch?, kernel_min?, kernel_max? }]`

The implementation should validate this schema with Pydantic models rather than ad hoc dict access.
Unknown fields are errors, so custom profiles fail early when misspelled.
`conflicts = []` is intentionally not a B1 schema field. Base-profile exclusivity handles current hard
conflicts; add-on combinations warn rather than fail. Add explicit add-on conflicts later only if real
impossible combinations appear.
Warning selectors determine whether a warning applies. B1 supports `arch`, `accel`, `host_os`, and
`profiles` selectors. Selectors combine with AND semantics. `profiles` means "emit this warning when all
listed profiles are also active."
Runtime defaults do not support selectors in B1. Use a simple nested table such as:

```toml
[runtime_defaults.debuggee]
kaslr = true
smep = true
smap = true
kpti = true
```

Boot arguments are structured entries with selectors. B1 supports `arch`, `kernel_min`, `kernel_max`, and
`profiles` selectors for `[[boot_arg]]`; applicable entries are flattened into `RunResolution.extra_boot_args`.
Boot-arg selectors use the same AND/profile-list semantics as warnings, except that B1 accepts but does not
evaluate `kernel_min` and `kernel_max` on boot args. Version-gated boot args should be treated as a no-op
selector in B1 and recorded as a TODO for the later stage that can evaluate boot args after the built-tree
version is known. This preserves the schema without forcing B1 to solve pre-boot version-dependent command
line generation.

Expectation selectors determine applicability before severity is evaluated:

- If `arch` is present and the current target arch is not listed, skip the expectation.
- If `kernel_min` is present and the built kernel version is older, skip the expectation.
- If `kernel_max` is present and the built kernel version is newer, skip the expectation.
- If all selectors match or no selectors are present, evaluate `severity`: missing `hard` expectations fail;
  missing `soft` expectations warn.

Kernel-version selectors use the Kernel Build's Makefile-derived version, not the requested
`mmp`/`tag`/`commit` string. `ProfileVerificationStage` reads `VERSION`, `PATCHLEVEL`, `SUBLEVEL`, and
`EXTRAVERSION` from the built tree for fresh builds and cache hits before evaluating `kernel_min` and
`kernel_max`. This keeps commit, tag, and cached-build paths accurate.

Arch selectors use the resolved concrete target architecture (`x86_64` or `arm64`), never the symbolic
config value `native`.

Resolution rules:

- If no profiles are configured, resolve to base profile `exploit-dev`.
- If only add-on profiles are configured, implicitly add base profile `exploit-dev`.
- If more than one base profile is configured, raise a `ConfigError` with a remedy to choose one.
- If a profile implies another add-on profile, de-duplicate while preserving deterministic fragment order.
- `kasan` and `ubsan` imply `crash-debug`, so `--profile kasan` resolves to
  `exploit-dev, crash-debug, kasan` and `--profile hardened,kasan` resolves to
  `hardened, crash-debug, kasan`.
- User profile order does not affect fragment order. The resolver imposes deterministic ordering: base
  profile first, implied add-ons next, explicit add-ons in profile registry order, and future user custom
  fragments last. Equivalent profile sets must produce the same fragment order and cache key.
- Profile registry order is deterministic by profile filename, with built-in and user-added files all loaded
  from `configs/profiles/`.
- Add-on combinations are allowed by default. Known slow, noisy, or brittle combinations should warn rather
  than hard-fail unless they are known to be impossible. Examples: `kasan + lockdep`, `kasan + kcov-lite`,
  or broad instrumentation under TCG.

Profile logs are operator-facing and visible without `-v`:

- resolved profile list: `INFO`
- runtime override notes: `INFO`
- profile composition/performance/brittleness warnings: `WARNING`

### 5.4 Profile and Runtime Compatibility

Profile resolution compares the resolved Debug profiles against runtime `DebuggeeCfg`.

Config provenance is required for profile-provided runtime defaults. The loader should expose, at least for
debuggee runtime toggles, whether each value came from a built-in default, a profile default, a tracked
project/default config, a user/workspace config, a scenario/custom config, or CLI. Profile runtime defaults
may replace inherited built-in/project defaults, but must not silently replace explicit user/scenario/CLI
values.

Target precedence, highest first:

1. CLI overrides
2. scenario/custom TOML config (`-c`)
3. user/workspace TOML config
4. profile-provided runtime defaults
5. tracked project/default TOML config
6. built-in model defaults

Normal user docs should present only three visible layers:

1. project defaults
2. local/scenario config
3. CLI overrides

The six-layer provenance model is internal/debuggable state for correct effective settings and run artifacts,
not six concepts the user must keep in working memory.

Modern TOML config files:

- `configs/default.toml`: tracked project defaults.
- `configs/local.toml`: gitignored workspace/user overrides.
- `configs/local.example.toml`: tracked example for local overrides.
- `configs/scenarios/*.toml`: named scenario configs, passed with `-c`.

Migration direction:

- `configs/system.ini` becomes `configs/default.toml`.
- `configs/user.ini` becomes `configs/local.example.toml` or a scenario TOML, depending on its content.
- add `configs/local.toml` to `.gitignore`.
- remove legacy INI runtime config loading; no fallback path reads `configs/system.ini` or `configs/user.ini`.

New default target architecture:

```toml
[general]
arch = "native" # native | x86_64 | arm64
```

`native` resolves to the host architecture through `HostProfile` before build recipes, profile compatibility,
and QEMU/GDB command construction. Users can still pin cross-architecture targets with `arch = "x86_64"` or
`arch = "arm64"`.
`Settings.general.arch` keeps the requested value (`native`, `x86_64`, or `arm64`) for requested-settings
artifacts. `RunResolution.target_arch` holds the concrete resolved architecture and is what BuildRecipe,
profile expectation selectors, QEMU, and GDB use.
Build cache identity and labels use `RunResolution.target_arch`, not the symbolic requested value `native`,
because a Kernel Build is identified by what was actually built.

If a profile runtime default is superseded by user/scenario/CLI config, log an `INFO` runtime override note
and record it in `profiles.json` and `run.json.warnings`.

Hard-error when runtime config asks for behavior the built kernel cannot support:

- `exploit-dev` disables `CONFIG_RANDOMIZE_BASE`, so `[debuggee] kaslr = yes` is invalid.
- Any profile that intentionally omits a sanitizer's required build-time support cannot accept a runtime
  request that implies that sanitizer is available.
- Architecture-specific expectations that are impossible on the chosen arch should fail if the profile
  declares them hard requirements.

Warn or note when runtime config overrides behavior that the built kernel still supports:

- `hardened` compiles KASLR support in; `[debuggee] kaslr = no` is allowed and should
  be logged as a runtime override that adds `nokaslr`.
- A profile contributes a suggested boot arg and the user config supplies a conflicting runtime knob that
  has a defined QEMU/kernel command-line representation.
- `hardened` contributes runtime defaults that turn mitigations on; explicit user settings may override
  them and should be logged as runtime override notes.

The profile module owns this compatibility check so `cli.py`, `qemu.py`, and individual stages do not
grow scattered special cases. TOML profile files define profile facts and `.config` expectations only;
runtime compatibility rules live as small named, unit-tested Python checks inside `debug_profiles.py`.

### 5.5 Settings and Cache Identity

Add `DebuggingCfg` to `src/likedbg/config.py`:

```python
class DebuggingCfg(_Base):
    profiles: str = "exploit-dev"
```

The loader accepts TOML profile lists. CLI parsing accepts one comma-separated `--profile` string and
normalizes it with the same validation path.

Build cache identity remains based on what is actually built. Since profile resolution contributes kconfig
fragments, the existing fragment hashes in `BuildRecipe` continue to invalidate builds correctly. The profile
names themselves do not need to be part of the Kernel Build key if they resolve to identical fragment content.
Run artifacts still record profile names for operator clarity.

Profile TOML files are also build inputs for the profile resolution result and should be recorded in run
artifacts. They do not need to be hashed into the Kernel Build key independently as long as every build-time
effect they cause is represented by fragment content. If a future profile property changes the build without
changing fragments, that property must be added to the BuildRecipe inputs in the same change.

### 5.6 Pipeline Integration

Current `cli.py` has a fixed `_FRAGMENTS` tuple. B1 replaces that with resolved profile fragments:

1. Parse settings and CLI profile overrides.
2. Resolve the run with `debug_profiles.resolve_run(...)`.
3. Log profile warnings/runtime notes at startup.
4. Pass `run_resolution.fragments` into `make_build_recipe`.
5. Insert `ProfileVerificationStage` after `BuildStage` and before `RootfsStage`.

`ProfileVerificationStage` must run for both fresh builds and cache hits. It consumes the built tree's
`.config`, verifies the resolved expectations, writes the result into the run artifacts when a recorder
exists, and raises a clear `BuildError` for missing hard expectations.
The stage receives the `RunResolution` and an optional `RunRecorder`. On success it records verification and
copies `.config` into the run artifacts when a recorder exists. On failure it records verification, sets run
status `profile-verification-failed`, then raises `BuildError`.
`DebuggeeStage` and `DebuggerStage` also receive the optional `RunRecorder`. They record their own argv and
shell command because those stages own command construction. Launch status transitions stay narrow:
`launching` is set before Debuggee launch, `launch-failed` is set if either launch fails, and `launched` is
set after the Debugger pane launch succeeds.

Invariant: no interactive Debuggee launch happens until profile verification passes. This applies to fresh
default runs, build cache hits, `--use <build-label>`, bind mode, and volume mode. If verification cannot
read `.config`, fail before boot with a remedy to rebuild or clean the cached Kernel Build.

`--use <build-label>` verifies the cached Kernel Build against the current requested Debug profiles, not
against whatever profiles were active when the Kernel Build was originally created. A mismatch is a hard
failure with a remedy to run without `--use` and build a Kernel Build for the requested profiles, or to choose
profiles that match the cached build. Run artifacts should record the requested profiles and the cached build
label even when verification fails.

Reading `.config` must work in both storage modes:

- bind mode: host-visible tree under `artifacts/ksrc/<label>`.
- volume mode: helper container reads from `likedbg_ksrc` at `/ksrc/<label>`.

Use a small reader module or private helper so the stage interface stays narrow.

### 5.7 Boot Args

Profiles may contribute additional kernel command-line args. B1 wires the mechanism but keeps the initial
profiles conservative. The QEMU builder should receive a resolved extra boot-arg list from context instead
of letting profiles edit `qemu.py` directly.

`kernel_min` and `kernel_max` are legal on `[[boot_arg]]` entries but are not evaluated in B1. B1 should
emit a low-noise TODO/deferred note when such selectors are present, and otherwise leave version-gated boot
args out of active behavior until a later slice defines the build-version-aware evaluation point.

Initial likely boot args:

- `exploit-dev`: no additional args beyond current mitigation handling.
- `kasan`: no allocator-debug boot args by default in B1.

`slub_debug=FZP` is intentionally not part of the built-in `kasan` profile in B1. It changes allocator
behavior enough that it should become a later explicit `slub-debug` add-on profile if we want it.

Any profile-provided boot arg must be recorded in run artifacts.

## 6. B2: Run Artifacts and Pane Transcript Capture

### 6.1 Run Directory Layout

Every default run and `--use` run creates:

```text
artifacts/runs/<YYYYMMDDTHHMMSSZ>-<build-label>/
  run.json
  settings.requested.json
  settings.effective.json
  host.json
  profiles.json
  profiles/
    configs/
      profiles/
        exploit-dev.toml
        crash-debug.toml
  fragments/
    configs/
      fragments/
        generic.config
        debug.config
        no-kaslr.config
  commands/
    qemu.sh
    gdb.sh
    qemu.argv.json
    gdb.argv.json
  logs/
    likedbg.log
    debuggee-pane.log
    debugger-pane.log
  kernel/
    config
    System.map.pointer
    vmlinux.pointer
    image.pointer
  notes.md
```

Also maintain:

```text
artifacts/runs/latest -> <run-id>
artifacts/logs/latest.log -> artifacts/runs/<run-id>/logs/likedbg.log
```

If symlink creation fails on a platform, write a small text file containing the target path and continue.
`artifacts/runs/latest` is updated when `RunRecorder.start(...)` creates the run directory, not only after a
successful launch. Failed profile verification remains the latest run so troubleshooting commands inspect the
failure the operator just saw.

The run directory is only for interactive Debugging sessions. It is created before profile verification, so
failed verification still leaves durable operator evidence. A failed `--use old-build --profile hardened`
should still populate `settings.requested.json`, `settings.effective.json`, `host.json`, `profiles.json`,
the run logfile, and verification details explaining why boot did not proceed. Non-interactive cache/image
commands, including `--adopt` and `--adopt-rootfs`, do not create run directories.

`settings.requested.json` records the merged TOML configuration plus CLI overrides before profile-derived
resolution.
`settings.effective.json` records what LIKE-DBG actually used after profile resolution, compatibility checks,
profile-provided boot args, and runtime override notes.

`profiles.json` records the full resolution graph, not just profile names:

```json
{
  "requested": ["kasan"],
  "base": "exploit-dev",
  "resolved": ["exploit-dev", "crash-debug", "kasan"],
  "implied_by": {
    "crash-debug": ["kasan"]
  },
  "profile_files": [
    {
      "source": "configs/profiles/kasan.toml",
      "snapshot": "profiles/configs/profiles/kasan.toml",
      "sha256": "..."
    }
  ],
  "fragments": [
    {
      "source": "configs/fragments/profiles/kasan.config",
      "snapshot": "fragments/configs/fragments/profiles/kasan.config",
      "sha256": "..."
    }
  ],
  "extra_fragments": [
    {
      "source": "configs/fragments/local/demo.config",
      "snapshot": "fragments/configs/fragments/local/demo.config",
      "sha256": "..."
    }
  ],
  "warnings": [],
  "runtime_notes": []
}
```

Profile-specific warnings and runtime notes are stored in `profiles.json` and mirrored into `run.json.warnings`
with stable codes such as `profile-warning` and `runtime-override-note`, so tools can see summary warnings
without opening every detail file.

`run.json` is the schema-versioned index and first file for humans/tools to open:

```json
{
  "schema_version": 1,
  "run_id": "20260626T103000Z-linux-6.6.30-a1b2c3d4",
  "kind": "debugging-session",
  "status": "profile-verification-failed",
  "created_at": "2026-06-26T10:30:00Z",
  "build_label": "linux-6.6.30-a1b2c3d4",
  "rootfs_label": "rootfs-arm64-bookworm-deadbeef",
  "host": "host.json",
  "settings_requested": "settings.requested.json",
  "settings_effective": "settings.effective.json",
  "profiles": "profiles.json",
  "commands": {
    "qemu": "commands/qemu.sh",
    "gdb": "commands/gdb.sh"
  },
  "logs": {
    "likedbg": "logs/likedbg.log",
    "debuggee": "logs/debuggee-pane.log",
    "debugger": "logs/debugger-pane.log"
  },
  "warnings": [
    {
      "at": "2026-06-26T10:30:10Z",
      "code": "transcript-capture-failed",
      "message": "tmux pipe-pane failed for Debuggee pane %4"
    }
  ]
}
```

B2 supports this initial run status set:

- `created`: run directory exists; setup has not completed.
- `profile-verification-failed`: profile verification failed before Debuggee boot.
- `launching`: profile verification passed; panes/commands are being launched.
- `launched`: Debuggee and Debugger process panes were launched.
- `launch-failed`: failure after profile verification but before both panes launched.

B2 does not try to detect completion; interactive Debugging sessions can run indefinitely and pane processes
outlive `start_kgdb`. Crash/completion lifecycle states belong to later B3/B5 work.

Profiles do not mutate `Settings`. `Settings` remains the requested TOML/CLI config model. Profile resolution produces
a separate derived run object, `RunResolution`, that includes requested settings, resolved profiles,
profile-provided runtime defaults, user runtime overrides, extra boot args, runtime notes, and profile
warnings. `settings.effective.json` is a rendered projection of `Settings + RunResolution`; the in-memory
pipeline threads derived facts explicitly, for example as `ctx.extra_boot_args`, instead of rewriting
`settings.debuggee`.

### 6.2 Run Recorder Module Interface

Add `src/likedbg/run_artifacts.py`.

Primary public interface:

```python
class RunRecorder:
    @classmethod
    def start(
        cls,
        *,
        workspace: Path,
        requested_settings: Settings,
        run_resolution: RunResolution,
        host: HostProfile,
        build_label: str,
        rootfs_label: str,
        profiles: ResolvedDebugProfiles,
    ) -> RunRecorder: ...

    def set_status(self, status: RunStatus, *, message: str | None = None) -> None: ...
    def add_warning(self, code: str, message: str) -> None: ...
    def record_command(self, kind: Literal["qemu", "gdb"], *, shell: str, argv: list[str]) -> None: ...
    def record_profile_verification(self, verification: ProfileVerification) -> None: ...
    def record_kernel_paths(self, *, config: Path | str, system_map: Path | str, vmlinux: Path | str, image: Path | str) -> None: ...
```

Important exposed paths:

- `run_dir`
- `likedbg_log`
- `debuggee_pane_log`
- `debugger_pane_log`

The interface intentionally does not expose the directory layout except through those paths.
`RunRecorder` owns `run.json` status updates. `set_status(...)` writes `run.json` atomically and appends a
UTC timestamped `status_history` entry with the optional message.

### 6.3 Log Setup Integration

Move the per-run file sink into the run directory:

```python
logsetup.add_run_logfile(workspace, path=recorder.likedbg_log)
```

Keep existing `artifacts/logs/latest.log` behavior for compatibility, but point it at the run directory's
`logs/likedbg.log`.
The compatibility pointer updates when the run logfile is added, so profile-verification failures also point
`artifacts/logs/latest.log` at the failed run's log.

Non-interactive commands (`--list`, `--clean`, `--build-images`, `--adopt`, `--adopt-rootfs`) still do not
create run directories.
`--explain-config` is also non-interactive and does not create a run directory.

### 6.4 Transcript Capture

Use tmux pane piping rather than QEMU-specific logging for B2. It is portable across native-host QEMU,
in-container QEMU, GEF, pwndbg, macOS, and Linux, and it preserves interactivity.

B2 transcripts are operator-pane transcripts, not byte-perfect serial capture. A small amount of output may
be missed between process-pane creation and `pipe-pane` activation. This limitation must be documented in
the run artifact `notes.md` and README-facing usage text. If B3 crash parsing needs byte-perfect capture,
that should be added later with QEMU-specific serial/chardev logging without replacing pane transcripts.

Add to `Session`:

```python
def pipe_pane(self, *, pane: str, output: Path) -> None
```

Implementation uses `tmux pipe-pane -o -t <pane> 'cat >> <quoted-output>'`.
`pipe_pane` is a separate primitive; `run_in_new_pane` continues to only create the process pane and return
its pane id. Callers launch first, then opt into transcript capture by calling `pipe_pane`.

Call flow:

1. Launch Debuggee process pane.
2. Immediately pipe that pane to `logs/debuggee-pane.log`.
3. Launch Debugger process pane.
4. Immediately pipe that pane to `logs/debugger-pane.log`.

This captures what the operator would otherwise lose from scrollback. The first design stays tmux-native
and does not claim byte-perfect serial logging.

### 6.5 Command Recording

The Debuggee and Debugger stages already build argv lists and shell commands before launch. B2 records both:

- argv JSON for exact structured reconstruction.
- shell script for quick human inspection.

The shell scripts are evidence, not executable state. Restart continues to use tmux session options as today.

### 6.6 Kernel Path Recording

Record pointers rather than copying large artifacts:

- `.config`: copy the text into `kernel/config`, because it is small and central to B1 verification.
- profile TOML definitions: copy only the resolved profile files, including implied profiles, into
  `profiles/`, preserving their relative paths, because they are small and preserve what the run meant even
  if the repo changes later. Do not copy unrelated profiles from the registry.
- kconfig fragments: copy the resolved fragment files into `fragments/` for the same reason. Fragment
  content directly affects the Kernel Build and should remain inspectable after the repo changes. Preserve
  relative paths to avoid filename collisions.
- `System.map`: pointer file to avoid unnecessary duplication.
- `vmlinux`: pointer file.
- kernel image: pointer file.
- rootfs image: pointer file.
- kernel source tree: pointer file.

For volume mode paths that are container-only, record both the container path and the host/export path when
available. The run artifact should make path ambiguity explicit.

## 7. Errors and User Feedback

Unknown profile:

```text
unknown debug profile 'asan'
remedy: choose one of exploit-dev, hardened, crash-debug, kasan, ubsan, lockdep, kcov-lite
```

The remedy list is generated from the discovered profile registry, so custom profiles placed in
`configs/profiles/` appear automatically in deterministic filename order.

Missing hard expectation:

```text
debug profile verification failed: kasan requested CONFIG_KASAN=y, but final .config has '# CONFIG_KASAN is not set'
remedy: inspect artifacts/runs/latest/profiles.json or remove the kasan profile
```

Transcript capture failure should warn and continue. It should not abort a working debug session unless the
run directory itself cannot be created.
Transcript capture failure does not set `launch-failed`. If `pipe_pane` fails for either process pane,
LIKE-DBG logs a warning, records a run warning, and continues; the run may still reach `launched`.

## 8. Testing Strategy

Unit tests:

- `debug_profiles.parse_profile_names`: TOML lists, comma-separated CLI strings, defaults, duplicate
  elimination.
- `debug_profiles` profile-definition loading: schema validation, missing files, unknown fields, bad
  `kind`, invalid expectation severity.
- `debug_profiles.resolve_run`: default `exploit-dev`, multiple profiles, unknown profile, fragment
  order, warnings.
- `debug_profiles.verify_config`: hard pass, hard fail, soft warning, `CONFIG_FOO is not set` parsing.
- `input_hash.hash_tree`: deterministic ordering, content changes affect the aggregate hash, ignored build
  junk is excluded, path traversal is not accepted by callers, empty directories are stable.
- `RunRecorder.start`: directory layout, JSON content, latest symlink/text fallback.
- `RunRecorder.record_command`: argv JSON and shell file output.
- `Session.pipe_pane`: exact tmux command construction and quoted path handling.
- `ProfileVerificationStage`: reads config in bind mode and volume mode, raises `BuildError` only on hard
  failures.

CLI tests:

- default run resolves `exploit-dev` and passes its fragments to `BuildRecipe`.
- comma-separated `--profile kasan,lockdep` overrides config profiles; repeated `--profile` flags are rejected.
- `--explain-config [text|json]` prints resolved layers/profiles/effective settings and creates no run
  directory; `json` emits stable machine-readable output.
- `--use` creates a run directory and records the cached build/rootfs labels.
- failed profile verification still creates a run directory with `profiles.json` and verification details.
- non-interactive commands do not create run directories.

Live gates:

1. Default arm64 run on the M5: build/reuse, boot, attach, run dir exists, pane logs receive output, profile
   verification passes.
2. x86_64-on-Mac `--use` run: run dir exists, debuggee/debugger transcripts are captured under in-container
   TCG, and profile verification runs before boot.
3. Linux bind-mode smoke when available: run dir path recording uses host-visible kernel tree paths.
4. Optional expensive gate: one `--profile kasan` build on the fastest available arch. If too slow for the
   main branch, document it as manual verification but keep unit coverage strict.

## 9. Definition of Done

- `docs/superpowers/ROADMAP.md` names B1-B6 and points at this spec.
- the modern TOML config documents `[debugging] profiles = ["exploit-dev"]`.
- runtime config is fully TOML-based; legacy INI config loading is removed with no fallback path.
- `uv run ./start_kgdb` preserves today's default behavior through the explicit `exploit-dev` profile.
- `uv run ./start_kgdb --profile kasan` affects the build recipe and records profile warnings/verification.
- Fresh builds and cache hits both verify the final `.config`.
- Every interactive run creates `artifacts/runs/<run-id>/` and updates `artifacts/runs/latest`.
- `artifacts/runs/latest/logs/debuggee-pane.log` and `debugger-pane.log` are populated during a real run.
- `artifacts/runs/latest/settings.requested.json`, `settings.effective.json`, `host.json`, `profiles.json`,
  and command files are useful enough for B3/B4/E to consume without scraping arbitrary terminal history.
- Full unit suite, mypy, and ruff pass.

## 10. Grill Decisions (2026-06-26 session)

A second `grill-with-docs` session resolved the remaining load-bearing/under-decided corners against
the actual code. These decisions AMEND the body above where they conflict; the implementation plan
(`docs/superpowers/plans/2026-06-26-modern-debugging-ux-b1-b2-plan.md`) follows these, not the original
phrasing.

1. **Effective runtime toggles live on `RunResolution.effective_debuggee` (a full `DebuggeeCfg`).**
   `resolve_run` computes the 6-layer precedence merge (profile defaults at layer 4); QEMU/GDB read
   `ctx.effective_debuggee`, never `ctx.settings.debuggee`. Requested `Settings` stays frozen.
   `settings.effective.json` renders from `effective_debuggee` + provenance.
2. **Whole-Settings per-key provenance.** The loader becomes a deep module
   `load_config(...) -> ConfigResolution(settings, provenance)` recording the winning layer for every
   `(section, key)`. Profile runtime defaults inject as a named layer-4 contributor. Replaces the
   flatten in `config.py:_layer`.
3. **`native` resolves inside `HostProfile.detect`** (new `HostProfile.target_arch` field).
   `resolve_run` takes `host` and reads `host.target_arch/accel/os` for selectors. `build_recipe` takes
   `arch` as an explicit parameter (`= host.target_arch`). `--use` keeps forcing the manifest arch, so
   `native` never reaches a cached-build recipe.
4. **Split `patch_dirs` (B1) from `custom_modules` (B6).** Patches mutate the kernel image, so they are
   applied in the kbuilder container in deterministic order and hashed into the **Kernel Build** cache
   identity. Out-of-tree `custom_modules` (vulnerable CTF/learning drivers) are NOT part of the Kernel
   Build identity and are deferred to B6 where build + guest `insmod` are designed together; B1 keeps
   only the validated schema slot (reject absolute/`..` paths).
5. **Verification reads host-side, not the tree per run.** `BuildStage` captures `.config` text and the
   Makefile-derived `kernel_release` into host-visible state recorded on the `Manifest` at build time.
   `ProfileVerificationStage` reads the host `.config` + `manifest.kernel_release` — zero per-run
   containers, protecting the volume-mode cache-hit UX. Legacy manifests fall back to a one-time
   helper-container read + backfill.
6. **`DebuggingCfg.profiles: tuple[str, ...] = ("exploit-dev",)`** (frozen model ⇒ tuple, not `str`).
   TOML lists pass through; the CLI comma-string is normalized through the same validation
   (lowercase, `[a-z0-9][a-z0-9._-]*`, non-empty); empty ⇒ `ConfigError`.
7. **Transcript capture is restart-aware.** The Debuggee pane-log absolute path is stored as
   `@likedbg_debuggee_pane_log` (added to `_SESSION_STATE_OPTIONS`); `cmd_restart_debuggee` re-pipes in
   append mode after respawning/recreating the pane. The Debugger pane is never restarted.
8. **Run-dir boundary = "`resolve_run` success → `RunRecorder.start`."** Errors in or before `resolve_run`
   (unknown profile, two bases, empty list, bad arch, no tmux) fail fast with NO run dir. Everything from
   `start` onward (verification/launch failure) leaves a run dir. CLI reorders to
   detect → resolve_run → build_recipe → start → attach-log → ensure-images → run. `resolve_run` warnings
   are captured in `profiles.json`/stderr, not the run log (run-id needs the build label first).
9. **Config stack:** two-phase load (select profiles, then finalize settings with provenance);
   `default.toml` tracked + required; `local.toml` auto-loaded if present (gitignored); `-c` is
   name-or-path (`-c lk01` → `configs/scenarios/lk01.toml`, or an explicit path). Migration:
   `system.ini` → `default.toml` (`arch="native"`, `[source] kind="mmp" value="6.6.30"`, real booleans);
   `user.ini` → `local.example.toml`. **`pwndbg` is the new de facto default** (`default.toml` + model
   default); `gef` is the local-override path — so the daily driver needs no `local.toml`.
10. **`[source]` model:** `SourceCfg(kind: "mmp"|"tag"|"commit", value: str)`. `resolve_version` returns
    the requested identifier (download + Label); selectors/verification use `manifest.kernel_release`.
11. **`--explain-config [text|json]`** renders the `RunResolution` minus post-build verification
    (`[[expect]]`/version-gated entries shown as `status: "pending-build"`). Docker-less, tmux-less, early
    branch in `main()`. One shared renderer with the run-artifact JSONs; provenance serialized as nested
    `{section: {key: layer}}`.
12. **Two compatibility checkpoints.** Resolution-time contradictions provable from declared facts
    (e.g. `exploit-dev` guarantees `CONFIG_RANDOMIZE_BASE is not set` + explicit `kaslr=on`) raise
    `ConfigError` in `resolve_run` (no run dir). Post-build `.config` failures (kconfig silently dropped a
    hard expectation) raise `BuildError` in `ProfileVerificationStage` (run dir + `profile-verification-failed`).
    Arch mismatches are handled by expectation selectors (skip), not a third failure case.

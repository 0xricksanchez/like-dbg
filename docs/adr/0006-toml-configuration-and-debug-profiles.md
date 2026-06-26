# Runtime configuration and Debug profiles use TOML with provenance

LIKE-DBG runtime configuration moves from the legacy `configs/system.ini` + `configs/user.ini`
model to a TOML configuration stack with explicit provenance. Debug profiles are TOML files under
`configs/profiles/` and compose kconfig fragments, post-build expectations, warnings, and profile
runtime defaults.

The modern runtime config files are:

- `configs/default.toml`: tracked project defaults.
- `configs/local.toml`: gitignored workspace/user overrides.
- `configs/local.example.toml`: tracked example for local overrides.
- `configs/scenarios/*.toml`: named scenario configs, passed with `-c`.

The conceptual precedence, highest first, is:

1. CLI overrides
2. scenario/custom TOML config (`-c`)
3. user/workspace TOML config
4. profile-provided runtime defaults
5. tracked project/default TOML config
6. built-in model defaults

Normal user documentation should present only three visible layers: project defaults,
local/scenario config, and CLI overrides. The full six-layer model exists so effective settings
and run artifacts can explain provenance precisely.

Debug profile TOML files define facts only: kind, implications, fragments, boot arguments,
warnings, runtime defaults, and `.config` expectations. Python owns compatibility logic such as
base-profile mutual exclusion and runtime contradictions.

There is no legacy INI fallback. The old INI files are migrated or replaced.

## Consequences

- Configuration, profile definitions, and scenario files use one format: TOML.
- `arch = "native"` is valid requested config, but build/cache/QEMU/GDB use the resolved concrete
  target architecture.
- Profiles may provide runtime defaults, such as `hardened` enabling mitigations by default, but
  explicit user/scenario/CLI settings win and are recorded as runtime override notes.
- Run artifacts can record both requested settings and effective settings with provenance.
- Legacy INI config loading is removed instead of kept as a compatibility path.

## Considered and rejected

- **Mixed TOML profiles with INI runtime config.** Rejected: it preserves the old split and makes
  provenance harder to explain.
- **Legacy INI fallback.** Rejected: this is a local rework branch; carrying both systems would add
  maintenance cost and keep ambiguous behavior alive.
- **TOML as a compatibility rules language.** Rejected: profile files stay declarative; runtime
  compatibility remains in tested Python code.

## Resolution (2026-06-26 grill)

A grill session against the shipped implementation confirmed and refined the following design
decisions. These amend any conflicting earlier text in this ADR.

1. **Whole-Settings provenance via `load_config -> ConfigResolution`.** The TOML loader is a deep
   module: `load_config(workspace, scenario=..., cli_overrides=...) -> ConfigResolution(settings,
   provenance)`. It records the winning layer for every `(section, key)` pair using six named layers
   (`builtin`, `project-default`, `profile-default`, `local`, `scenario`, `cli`). Profile runtime
   defaults inject as a named layer-4 contributor. This replaces the flat merge in the old
   `config.py:_layer` approach. Provenance is serialized as nested `{section: {key: layer}}` in
   `settings.effective.json` and in `--explain-config json` output.

2. **`native` resolves inside `HostProfile.detect` via `target_arch`.** `HostProfile` gains a
   `target_arch` field (concrete `"x86_64"` or `"arm64"`). `resolve_run` takes the `host` object
   and reads `host.target_arch` for profile expectation selectors, fragment ordering, and QEMU/GDB
   command construction. The symbolic value `"native"` never reaches a cached-build recipe. `--use`
   forces the manifest arch so `native` is substituted before cache lookup.

3. **Profile runtime defaults at layer 4 -> `effective_debuggee`.** `resolve_run` computes the
   full 6-layer precedence merge and places the result in `RunResolution.effective_debuggee` (a
   full `DebuggeeCfg`). QEMU and GDB read `ctx.effective_debuggee`, never the frozen requested
   `Settings.debuggee`. `settings.effective.json` renders from `effective_debuggee` plus provenance.
   The `hardened` profile is the canonical example: it contributes default `kaslr=true`,
   `smep=true`, `smap=true`, `kpti=true`; explicit user/scenario/CLI values override these and are
   recorded as runtime override notes.

4. **`pwndbg` is the de facto default; `gef` is the local-override path.** `configs/default.toml`
   ships `[debugger] ext = "pwndbg"`. Users who prefer GEF add `[debugger] ext = "gef"` to
   `configs/local.toml`. No `local.toml` is needed for the default pwndbg daily driver.

5. **Two-phase load.** The config stack is loaded in two phases: (a) select profiles from the
   TOML + CLI `--profile` argument; (b) finalize all settings with full provenance including
   profile-provided runtime defaults. This avoids a circular dependency between profile discovery
   and effective settings.

6. **`-c` is name-or-path.** The `-c` / `--config` argument accepts either a plain name
   (`-c lk01` resolves to `configs/scenarios/lk01.toml`) or an explicit path (any value
   containing `/` or ending in `.toml` is used as-is). No lookup when an explicit path is given.

7. **`custom_modules` deferred to B6; `patch_dirs` stays in B1.** Patch directories mutate the
   kernel image at build time and are hashed into the Kernel Build cache identity. Out-of-tree
   custom modules (CTF/learning drivers) are not part of Kernel Build identity and are deferred to
   B6 where the full guest build + `insmod` workflow is designed. B1 keeps the validated schema
   slot for `custom_modules` (rejects absolute paths and `..` traversal) but applies no build
   behavior to it.

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

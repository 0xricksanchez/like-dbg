# LIKE-DBG — Content-Addressed Build Reuse (the Build Cache)

- **Date:** 2026-06-23
- **Status:** Approved design (grilled), pending implementation plan
- **Author:** 0x434b (with Claude)
- **Glossary:** `CONTEXT.md` — Kernel Build, Label, Manifest, Build Cache, Debuggee.
- **Related ADRs:** 0001 (execution topology), 0002 (bind vs volume storage),
  0003 (Kernel Builds identified by requested config, not toolchain identity).

## 1. Context

The M1 foundation pipeline (Download → Unpack → Build → Rootfs → Export → Debuggee →
Debugger) and the one-command `start_kgdb` assembly are in place (M1 Plans 1–4). Wiring the
live gate (Plan 4, Task 5) surfaced a structural gap: the heavyweight stages are **not
reuse-aware**. `UnpackStage` always re-extracts; `BuildStage` always runs `make mrproper` +
`make all` (a full clean rebuild every run); Download/Rootfs had a related skip-context
defect (fixed in Plan 4 fold-back).

The consequence: every `start_kgdb` run rebuilds the kernel (~30–60 min on a 4-core/8 GB
colima VM, with OOM risk), and switching kernel versions/configs rebuilds each time. For a
daily-driver kernel-exploitation workflow — hopping between 6.6.30 and 6.1 and back — this
is unacceptable.

**Goal:** make reuse a *core, cross-layer* feature. A run with a given configuration must
transparently reuse a previously produced **Kernel Build** (and rootfs image) instead of
rebuilding, and multiple builds must coexist so several kernels can be debugged in
succession with zero rebuilds. The Plan-4 live boot+attach gate is folded in as this plan's
empirical exit.

## 2. Requirements (from brainstorming + grilling)

1. **Identity:** a Kernel Build is identified by an automatic content-hash of its *requested
   configuration*, surfaced as a human-readable **Label** (`linux-<version>[-<tag>]-<hash8>`).
   Identical config always reuses; any build-affecting config change yields a new entry.
2. **Scope:** the Kernel Build and the rootfs image are content-addressed and coexist.
   The host-side exported Image is part of a Kernel Build's *footprint* (not a third cache
   kind). The kernel download stays version-keyed by filename (shared across configs).
3. **No drift:** what is hashed == what is built, guaranteed by construction (a Recipe value
   object the stage builds *from*), not by convention.
4. **Lifecycle:** keep everything (no auto-eviction). An explicit command lists cached
   artifacts with sizes and removes selected ones (or all). `--force-rebuild` is the escape
   hatch to recompile a config that is already cached.
5. **Selection:** config-driven by default (compute the key from the active config →
   reuse-or-build) **and** direct launch by Label (`--use <label>`), backed by the Manifest.
6. **Cross-platform:** the design is storage-mode-aware (ADR-0002) so both macOS (volume +
   native-host QEMU) and Linux (bind + in-container QEMU) are first-class.

## 3. Non-goals / assumptions

- **Single-active-run.** One live Debuggee at a time — already enforced by the fixed QEMU
  gdbstub port `:1234` (ADR-0001). No file locking; multi-debuggee concurrency would be a
  separate gdbstub-port-allocation feature.
- **No auto-eviction** (LRU / size cap) — keep-all + manual clean.
- **No toolchain reproducibility.** The key identifies *requested config*, not the compiler
  *version* baked into the kbuilder image (ADR-0003).
- **No shared source tree across configs** — kernel builds are in-tree, so each keyed build
  is a full tree; accepted.
- **Download is not hash-keyed** — version-keyed filename, shared across configs, as-is.

## 4. Architecture

A dedicated cache module plus cache-aware stages. Stages stay thin; the cache module owns
key/label derivation, the Manifest registry, and storage-mode-aware location resolution.

```
   settings ─▶ cache.build_recipe()/rootfs_recipe() ─▶ Recipe (inputs + build params)
                          │                                  │
                          ▼                                  │ drives
   cache.cache_key()/label()/manifest I/O/locations()        ▼
                          │ consulted by            Unpack ─ Build ─ Rootfs ─ Export
                          └────────────────────────────────────┘
   CLI (cli.py): default | --use | --force-rebuild | --list | --clean | --adopt
```

### 4.1 Recipe, key & label (`src/likedbg/cache.py`)

The **no-drift guarantee is a type invariant**: a `BuildRecipe` is the single source of
truth, and the stage builds *only from the recipe* — never re-reading `settings`. Change an
input and both the key and the build move together.

```python
@dataclass(frozen=True)
class BuildRecipe:
    version: str
    arch: str
    compiler: str                 # clang | gcc  (choice, not version — ADR-0003)
    make_vars: dict[str, str]     # resolved toolchain env (ARCH=, LLVM=1 / CROSS_COMPILE=)
    fragments: tuple[Path, ...]   # concrete fragment files the build merges
    frag_hashes: dict[str, str]   # name -> sha256(content)

    def cache_inputs(self) -> dict[str, str]:        # the dict that gets hashed
        return {"version": self.version, "arch": self.arch,
                "compiler": self.compiler, **{f"frag:{k}": v for k, v in self.frag_hashes.items()}}

@dataclass(frozen=True)
class RootfsRecipe:
    arch: str
    distribution: str
    hostname: str
    def cache_inputs(self) -> dict[str, str]: ...

def cache_key(inputs: dict[str, str]) -> str:        # sha256(canonical json), full hex
def short_hash(key: str) -> str:                     # first 8
def slug(text: str) -> str:                          # fs-safe, lowercased
def build_label(recipe, key) -> str:                 # linux-<version>[-<tag>]-<hash8>
def rootfs_label(recipe, key) -> str:                # rootfs-<arch>-<distribution>-<hash8>
```

**Forward guard:** when patches / `custom_modules` / a rootfs package list are wired into
the stages, their inputs MUST be added to the corresponding recipe's `cache_inputs` in the
same change — they affect output and belong in the key (unlike toolchain identity, ADR-0003).

### 4.2 Storage-mode-aware footprint (ADR-0001/0002)

A Kernel Build's footprint depends on storage mode; the cache absorbs the difference so
everything downstream is mode-agnostic.

| | **volume mode** (macOS, case-insensitive) | **bind mode** (Linux; macOS case-sensitive) |
|---|---|---|
| kernel tree | `/ksrc/<label>/` (named volume) | `<ws>/artifacts/builds/<label>/` (host) |
| Image QEMU reads | host export `<ws>/artifacts/<label>/Image` | in-tree `…/arch/<arch>/boot/<Image\|bzImage>` |
| `vmlinux` mount source for the gdb container | named volume `likedbg_ksrc` ro | host dir `<ws>/artifacts/builds/<label>` ro |
| Export stage | copies Image → host (single file) | **skipped** — the build *is* the export |
| QEMU (ADR-0001) | native on host | in-container (`/dev/kvm`) |

`cache.locations(label, storage_mode)` returns this footprint. **Plan-4 gap to fix:**
`gdb_pane_command` currently hardcodes `-v likedbg_ksrc:/ksrc:ro`; the mount source must
come from `locations()` so bind mode works.

### 4.3 Manifest registry (host = source of truth, the mode-absorbing seam)

One JSON per cached artifact under `<ws>/artifacts/cache/{builds,rootfs}/<label>.json`
(`artifacts/` is git-ignored). It records the **resolved paths** downstream needs, so
`--use` / Debuggee / Debugger consume the Manifest and never branch on storage mode:

```json
{ "kind": "build", "label": "linux-6.6.30-gef-a1b2c3d4", "key": "<sha256>",
  "version": "6.6.30", "arch": "arm64", "storage_mode": "volume",
  "inputs": { "...": "..." },
  "kernel_root": "/ksrc/linux-6.6.30-gef-a1b2c3d4",
  "vmlinux_mount": { "source": "likedbg_ksrc", "type": "volume" },
  "vmlinux_in_container": "/ksrc/linux-6.6.30-gef-a1b2c3d4/vmlinux",
  "image_host": "artifacts/linux-6.6.30-gef-a1b2c3d4/Image",
  "created_at": "<iso8601>", "size_bytes": 0 }
```

- **Manifest present ⇒ cached.** Reuse = compute Label from the recipe → Manifest exists →
  populate context from it, skip produce.
- **Atomic write** (temp file + rename) on success only — a Manifest never exists for a
  partial build.
- `created_at`/`size_bytes` are stamped by the CLI after the stage returns (the workflow
  can't read the clock); the stage records paths.

### 4.4 Cache-aware stages

`PipelineContext` carries `build_label` + `rootfs_label`; stages resolve paths via the cache.
All keep the Plan-4 invariant: **populate context whether or not work was skipped.**

- **Unpack:** Manifest(build_label) exists → set `kernel_root`, skip extract. Else
  **`rm -rf` the keyed dir first** (an interrupted prior extract/build must not poison the
  rebuild), extract the archive into the keyed dir (strip top `linux-<ver>` dir), set
  `kernel_root`.
- **Build:** Manifest exists → set `vmlinux` + `kernel_image`, skip compile. Else build the
  keyed tree **from the BuildRecipe** (`mrproper`+`defconfig`+merge fragments+`olddefconfig`+
  `make all`), then write the build Manifest atomically; set `vmlinux` + `kernel_image`.
- **Rootfs:** Manifest(rootfs_label) exists → set `rootfs_image`. Else build
  `artifacts/rootfs/<rootfs_label>.img` from the RootfsRecipe, write Manifest, set it.
- **Export** (volume mode only): copy keyed Image → `artifacts/<label>/Image` (skip if
  present). On the **produce/first-export** path it **piggybacks a `test -e`** on the
  in-volume `Image`/`vmlinux` (near-free — it already runs a container here), failing fast
  with a clear `CacheError` if the volume artifact is gone.

**Reuse integrity:** host-side artifacts (rootfs image, host export Image) are free
`path.exists()` checks on reuse → missing ⇒ `CacheError` ("artifact gone — `--clean <label>`
and rebuild"). The in-volume `vmlinux` is trusted on cache hits (no per-run container probe,
which would defeat fast reuse); a wiped *volume* is the one documented edge → recover with
`--clean` / `--force-rebuild`.

### 4.5 CLI surface (`cli.py` / `start_kgdb`)

- **default:** load settings → derive build + rootfs recipes → labels → cache-aware pipeline
  → reuse-or-produce → drive tmux panes.
- `--force-rebuild`: recompile even on a cache hit (escape hatch, e.g. after a deliberate
  toolchain change — ADR-0003).
- `--use <label> [--rootfs <label>]`: load the build Manifest; run only Export(if needed) +
  Debuggee + Debugger from its resolved paths. **Precedence:** the Manifest's `arch` is
  authoritative and overrides `settings.general.arch` for the whole run (QEMU binary, accel/
  topology per ADR-0001, gdb `set architecture`, and the rootfs's arch); **runtime/debugger
  preferences come from the active config** (`ext`, `memory`, `smp`, `-append` mitigation
  toggles). The rootfs is resolved at the build's arch (`--rootfs` pins a cached one, else
  the active rootfs config rebased onto that arch → reuse-or-build). Unknown label or
  arch mismatch ⇒ `CacheError`.
- `--list`: print cached builds + rootfs (label, version, **arch**, size, created). Exit 0.
- `--clean <label>` / `--clean-all`: remove the mode-appropriate footprint
  (`locations()`) + Manifest(s) — volume dir via container `rm -rf`, host files via unlink.
- `--adopt`: one-time migration of the *single* legacy unkeyed `/ksrc/linux-<version>` into
  the cache. **Verified best-effort:** hard-refuse (`CacheError`) on **version** (tree
  `Makefile`) or **compiler-family** (`.config` `CONFIG_CC_VERSION_TEXT`) mismatch vs the
  active config; **warn** on fragments (defconfig+merge is lossy, can't fully reverse).
  On success: `mv` to `/ksrc/<label>` + atomic Manifest write — **no rebuild** (so no OOM
  exposure). Unblocks the live gate cheaply.

### 4.6 Error handling

New `CacheError(LikeDbgError)` with `remedy=`:
- unknown `--use`/`--rootfs` label → "run `start_kgdb --list`".
- `--adopt` version/compiler mismatch → "this tree was built differently; `--clean` and
  rebuild, or fix the active config".
- reuse finds a host artifact missing → "`--clean <label>` and rebuild".
- Export-time in-volume artifact missing (wiped volume) → "`--clean <label>` / `--force-rebuild`".
- malformed Manifest → `CacheError`; absent Manifest → "not cached" (normal).

## 5. Data flow (default run, cache hit, volume mode)

```
settings ─▶ BuildRecipe + RootfsRecipe ─▶ labels
   Download : ensure archive (version-keyed, host)             [idempotent]
   Unpack   : Manifest(build_label)? → kernel_root, skip         ← cache hit
   Build    : Manifest(build_label)? → vmlinux/Image, skip       ← cache hit
   Rootfs   : Manifest(rootfs_label)? → rootfs_image, skip       ← cache hit
   Export   : artifacts/<label>/Image present? → host image      [idempotent, host check]
   Debuggee : qemu argv (host Image + rootfs) → tmux pane 1
   Debugger : gdb argv (vmlinux via locations() mount) → pane 2
```

A miss on Build runs the full compile once and writes the Manifest; the next same-config run
is a hit. Bind mode is identical minus Export (the build is the export) and with a host-dir
`vmlinux` mount.

## 6. Testing strategy

**Unit (pure / fakes — no real Docker/QEMU):**
- `cache_key` determinism + sensitivity (any input change → different key); `build_label`/
  `rootfs_label` format + `slug` sanitization.
- **No-drift:** the same `BuildRecipe` yields both `cache_inputs()` and the build params;
  a test asserts the build consumes only recipe fields (e.g. via a recipe with sentinel
  values reflected in the issued make command).
- Manifest atomic round-trip (write→read equal); absent → "not cached"; malformed → `CacheError`.
- Each stage's two paths with a fake `ContainerService`: **reuse** (Manifest present → no
  container started, context populated) and **produce** (absent → `rm -rf` then work, atomic
  Manifest written, context populated). Reuse with a missing host artifact → `CacheError`.
- `cache.locations(label, storage_mode)` for both modes (volume vs bind footprints + mount
  source).
- CLI `--list` / `--clean` / `--clean-all` / `--use` (incl. arch-precedence + arch mismatch)
  / `--force-rebuild` / `--adopt` (version/compiler refuse, fragment warn) against a fake cache.

**Empirical (the live gate, now cheap):**
1. `start_kgdb --adopt` → existing `/ksrc/linux-6.6.30` adopted under its Label + Manifest.
2. `start_kgdb` (inside tmux) → cache hit on Unpack/Build/Rootfs → native HVF boot in pane 1,
   GEF at `start_kernel` in pane 2. Record the transcript.
3. A second config (e.g. different fragments) builds once; a third run hops back to the first
   via `--use <label>` with no rebuild.

## 7. Constraints (inherited)

- New code under `src/likedbg/`; tests under `tests/`; legacy flat `src/*.py` untouched.
  `mypy --strict` clean over `src/likedbg`; `ruff check`/`format` clean; line length 120;
  tools via `uv run`.
- Errors are `LikeDbgError` subclasses with `remedy=`; side-effects behind injected seams.
- Branching: `main` untouched; feature branch off `dev`; live validation folded in.
- Honors ADR-0001 (native QEMU on the Mac host in a tmux pane; gdb container with
  `--add-host=host.docker.internal:host-gateway`; `hbreak start_kernel`; colima context)
  and ADR-0002 (bind vs volume storage).

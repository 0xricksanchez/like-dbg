# LIKE-DBG — Content-Addressed Build Reuse ("build cache")

- **Date:** 2026-06-23
- **Status:** Approved design, pending implementation plan
- **Author:** 0x434b (with Claude)

## 1. Context

The M1 foundation pipeline (Download → Unpack → Build → Rootfs → Export → Debuggee →
Debugger) and the one-command `start_kgdb` assembly are in place (M1 Plans 1–4). Wiring
the assembly together for the live gate (Plan 4, Task 5) surfaced a structural gap: the
heavyweight stages are **not reuse-aware**.

- `UnpackStage` always re-extracts the archive into the kernel-source volume.
- `BuildStage` always runs `make mrproper` + `make all` — a full clean rebuild every run,
  even when an identical build already exists.
- `DownloadStage` and `RootfsStage` had a related defect (fixed in Plan 4 fold-back): a
  skipped stage never populated the pipeline context.

The consequence: every `start_kgdb` run rebuilds the kernel (~30–60 min on a 4-core/8 GB
colima VM, with OOM risk), and switching between kernel versions/configs means rebuilding
each time. For a daily-driver kernel-exploitation workflow — hopping between KernelA and
KernelB and back — this is unacceptable.

**Goal:** make build reuse a *core, cross-layer* feature. A run with a given configuration
must transparently reuse a previously produced build (kernel tree, rootfs image, exported
artifacts) instead of rebuilding, and multiple builds must coexist so the user can debug
several kernels in succession with zero rebuilds.

This is the empirical exit gate of Plan 4 (the live boot+attach) folded into a new,
self-contained milestone plan.

## 2. Requirements (from brainstorming)

1. **Cache identity:** an automatic content-hash of *stage-declared* build inputs, exposed
   through a **human-readable label** (`linux-<version>[-<tag>]-<hash8>`). Identical config
   always reuses; any build-affecting change yields a new entry. `kernel_tag` (if set)
   appears in the label for readability.
2. **Scope (all heavy layers):** the in-volume kernel build tree, the rootfs image, and the
   host-side exported artifacts are each content-addressed and coexist side-by-side.
3. **Hash inputs:** each cacheable stage declares the exact values it consumes; the same
   dict is both hashed and used to produce the artifact, so the key can never drift from
   what actually affects output.
4. **Lifecycle:** keep everything (no auto-eviction). An explicit management command lists
   cached builds with sizes and removes selected ones (or all).
5. **Selection:** config-driven by default (compute the key from the active config →
   reuse-or-build) **and** a direct launch by label (`--use <label>`) backed by a per-build
   manifest, so the user can boot a cached build without reconstructing its config.

## 3. Non-goals

- Auto-eviction (LRU / size cap) — explicitly out (keep-all + manual clean).
- Sharing one source tree across configs — kernel builds are in-tree, so each keyed build
  is a full tree; that is accepted.
- Remote/shared caches, reproducible-build guarantees, or build provenance beyond the
  manifest. Hashing identifies *config*, not bit-for-bit toolchain reproducibility.
- Caching the kernel **download** by hash — the archive is already version-keyed by filename
  and shared across configs; it stays as-is.

## 4. Architecture

A dedicated cache module plus cache-aware stages. Stages stay thin; the cache module owns
key/label derivation, the manifest registry, and artifact-location resolution.

```
                        ┌─────────────────────┐
   settings  ──────────▶│  likedbg/cache.py   │
                        │  - *_cache_inputs()  │  derive inputs (per domain)
                        │  - cache_key()       │  sha256(canonical json)
                        │  - build_label()     │  linux-<ver>[-<tag>]-<hash8>
                        │  - Manifest I/O      │  artifacts/cache/{builds,rootfs}/*.json
                        │  - locations()       │  volume vs bind path resolution
                        │  - presence/list/rm  │
                        └─────────┬────────────┘
                                  │ consulted by
   Unpack ─ Build ─ Rootfs ─ Export ─ Debuggee ─ Debugger   (cache-aware)
                                  │
                                  ▼
                         CLI (cli.py): default | --use | --list | --clean | --adopt
```

### 4.1 Cache key, label & stage-declared inputs (`src/likedbg/cache.py`)

```python
CacheInputs = dict[str, str]   # flat, JSON-serializable

def cache_key(inputs: CacheInputs) -> str:
    blob = json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()        # full hex

def short_hash(key: str) -> str:                            # first 8
    return key[:8]

def slug(text: str) -> str: ...                             # fs-safe, lowercased

def build_label(*, version: str, kernel_tag: str, key: str) -> str:
    tag = f"-{slug(kernel_tag)}" if kernel_tag else ""
    return f"linux-{slug(version)}{tag}-{short_hash(key)}"

def build_cache_inputs(settings, *, version: str, fragments: list[Path]) -> CacheInputs:
    # exactly what BuildStage consumes
    out = {"version": version, "arch": settings.general.arch,
           "compiler": settings.kernel_builder.compiler,
           "toolchain": settings.kernel_builder.toolchain}
    for f in sorted(fragments):
        out[f"frag:{f.name}"] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out

def rootfs_cache_inputs(settings) -> CacheInputs:
    return {"arch": settings.general.arch,
            "distribution": settings.rootfs.distribution,
            "hostname": settings.rootfs.hostname}

def rootfs_label(settings, key) -> str:
    return f"rootfs-{slug(settings.general.arch)}-{slug(settings.rootfs.distribution)}-{short_hash(key)}"
```

The build cache inputs are derived in one place (the build domain) and consumed by **both**
Unpack and Build (which together produce the cached tree) and by label computation.

### 4.2 Storage layout

| artifact | volume mode (macOS, primary) | bind mode (Linux) |
|---|---|---|
| kernel tree | `/ksrc/<label>/` | `<ws>/artifacts/builds/<label>/` |
| vmlinux | `/ksrc/<label>/vmlinux` (gdb container reads it) | `<ws>/artifacts/builds/<label>/vmlinux` |
| in-tree Image | `/ksrc/<label>/arch/<arch>/boot/<Image\|bzImage>` | same under bind dir |
| exported Image (host) | `<ws>/artifacts/<label>/Image` (native QEMU reads it) | n/a (bind = no export) |
| rootfs image (host) | `<ws>/artifacts/rootfs/<rootfs_label>.img` | same |
| manifests (host) | `<ws>/artifacts/cache/{builds,rootfs}/<label>.json` | same |

### 4.3 Manifest registry (host = source of truth)

One JSON per cached artifact, written by the producing stage on success:

```json
{ "kind": "build", "label": "linux-6.6.30-gef-a1b2c3d4",
  "key": "<full-sha256>", "version": "6.6.30", "arch": "arm64",
  "inputs": { "...": "..." },
  "kernel_root": "/ksrc/linux-6.6.30-gef-a1b2c3d4",
  "vmlinux": "/ksrc/linux-6.6.30-gef-a1b2c3d4/vmlinux",
  "image_host": "artifacts/linux-6.6.30-gef-a1b2c3d4/Image",
  "created_at": "<iso8601>", "size_bytes": 0 }
```

**Manifest present ⇒ artifact cached.** Reuse = compute label from inputs → manifest exists
→ skip produce, populate context from manifest. This avoids a per-check container probe.
Trade-off: wiping the volume out-of-band leaves a stale manifest; recover with `--clean`.
`created_at`/`size_bytes` are stamped by the caller after the workflow (scripts cannot read
the clock); the stage records paths and the CLI fills timing/size.

### 4.4 Cache-aware stages

`PipelineContext` gains `build_label: str | None` and `rootfs_label: str | None`. The CLI
computes both up front (from the active config) and the stages resolve paths via the cache.

- **Unpack:** manifest for `build_label` exists → set `kernel_root` to the keyed dir, skip
  extract. Else extract the archive into `/ksrc/<label>/` (strip the top `linux-<ver>` dir),
  set `kernel_root`.
- **Build:** manifest exists → set `vmlinux` + `kernel_image`, skip compile. Else
  `mrproper`+`defconfig`+merge fragments+`olddefconfig`+`make all` in the keyed dir, then
  write the build manifest; set `vmlinux` + `kernel_image` (volume paths).
- **Rootfs:** manifest for `rootfs_label` exists → set `rootfs_image`. Else build
  `artifacts/rootfs/<rootfs_label>.img`, write manifest, set `rootfs_image`.
- **Export** (volume mode only): copy keyed Image → `artifacts/<label>/Image` (skip if
  present), set host `kernel_image`; `vmlinux` stays in the volume.

All four keep the Plan-4 idempotency invariant: **populate context whether or not work was
skipped.**

### 4.5 CLI surface (`cli.py` / `start_kgdb`)

- **default:** load settings → compute build+rootfs labels → assemble cache-aware pipeline
  → run → drive tmux panes. Reuses cached build/rootfs if present; else produces them.
- `--use <label>` (+ optional `--rootfs <label>`): load the build manifest; run only
  Export(if needed) + Debuggee + Debugger from its artifacts. The rootfs is independent of
  the build: `--rootfs <label>` pins a specific cached rootfs; otherwise the rootfs is
  resolved from the **active config** (`rootfs_label` → reuse if cached, else build it once).
  So `--use` is zero-rebuild whenever the rootfs is already cached (the common case).
  Unknown build/rootfs label → `CacheError` listing available labels.
- `--list`: print cached builds + rootfs (label, version, arch, size, created). Exit 0.
- `--clean <label>` / `--clean-all`: remove artifact(s) + manifest(s) — volume dir via a
  container `rm -rf /ksrc/<label>`, host files via unlink. Exit 0.
- `--adopt`: one-time migration. Compute the label for the active config, verify
  `vmlinux` + Image exist in the legacy unkeyed `/ksrc/linux-<version>`, `mv` it to
  `/ksrc/<label>`, and write its manifest. Pulls the known-good Plan-3 build into the cache
  so the live gate runs with **zero rebuild**.

### 4.6 Error handling

- New `CacheError(LikeDbgError)` with `remedy=` (e.g. unknown `--use` label → "run
  `start_kgdb --list`"; `--adopt` with no legacy tree → "build once or pass the right
  config"; manifest points at a missing artifact → "`--clean <label>` and rebuild").
- Manifest read tolerates absence (treated as "not cached"); malformed manifest → `CacheError`.

## 5. Data flow (default run, cache hit)

```
settings ─▶ build_cache_inputs + rootfs_cache_inputs ─▶ labels
   Download   : ensure archive (version-keyed, host)            [idempotent]
   Unpack     : manifest(build_label)? → kernel_root, skip       ← cache hit
   Build      : manifest(build_label)? → vmlinux/Image, skip     ← cache hit
   Rootfs     : manifest(rootfs_label)? → rootfs_image, skip     ← cache hit
   Export     : artifacts/<label>/Image present? → host image    [idempotent]
   Debuggee   : qemu argv (host Image + rootfs) → tmux pane 1
   Debugger   : gdb argv (volume vmlinux) → tmux pane 2
```

A cache *miss* on Build runs the full compile once and writes the manifest; the next run
with the same config is a hit.

## 6. Testing strategy

**Unit (pure / fakes — no real Docker/QEMU):**
- `cache_key` determinism (same inputs → same key) and sensitivity (any input change →
  different key); `build_label`/`rootfs_label` format + slug sanitization.
- Manifest round-trip (write → read → equal); absent manifest → "not cached"; malformed →
  `CacheError`.
- Each stage's two paths with a fake `ContainerService`: **reuse** (manifest present → no
  container started, context populated from manifest) and **produce** (absent → container
  work happens, manifest written, context populated).
- CLI `--list` / `--clean` / `--clean-all` / `--use` / `--adopt` against a fake cache.
- Pipeline assembly: labels threaded into context; `--use` builds a launch-only pipeline.

**Empirical (the live gate, now cheap):**
1. `start_kgdb --adopt` → existing `/ksrc/linux-6.6.30` adopted under its label + manifest.
2. `start_kgdb` (inside tmux) → cache hit on Unpack/Build/Rootfs → native HVF boot in pane
   1, GEF at `start_kernel` in pane 2. Record the transcript.
3. Sanity: a second config (e.g. different fragments) builds once, then a third run hops
   back to the first via `--use <label>` with no rebuild.

## 7. Constraints (inherited)

- New code under `src/likedbg/`; tests under `tests/`; legacy flat `src/*.py` untouched.
  `mypy --strict` clean over `src/likedbg`; `ruff check`/`format` clean; line length 120;
  run tools with `uv run`.
- Errors are `LikeDbgError` subclasses with `remedy=`; side-effects behind injected seams.
- Branching: `main` untouched; feature branch off `dev`; live validation folded in.
- Honors the Plan 2/3 bring-up facts: native QEMU on the Mac host (tmux pane), gdb
  container with `--add-host=host.docker.internal:host-gateway` mounting the kernel volume
  ro, `hbreak start_kernel`, colima docker context.

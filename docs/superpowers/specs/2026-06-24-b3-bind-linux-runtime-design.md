# B3 — Un-gate the bind/Linux runtime — Design

**Date:** 2026-06-24
**Status:** approved (brainstormed + grilled against CONTEXT.md / ADR-0001 / ADR-0002); no new ADR —
realizes ADR-0002 (bind mode) and ADR-0001 (topology); `Network mode` added to `CONTEXT.md`.
**Branch:** `feat/b3-bind-linux` off `dev` → merged **locally** (per ROADMAP: `dev` stays local).
**ROADMAP item:** §B foundation-completion, piece 3 of 3 (after B1+B2). B2 built the in-container launch
seam (`qemu_container_command`, `DebuggeeStage` dispatch, arch-aware gdb) that B3 reuses on Linux.

## 1. Context

The runtime is hard-gated to **volume** storage: `cli.require_volume_mode` raises on any
`storage_mode != "volume"`, and `host_profile._resolve_storage` returns `"bind"` for *every*
non-darwin OS — so the tool cannot run on Linux at all today. Per **ADR-0002**, Linux is **bind
mode** by design (kernel source bind-mounted, **host-editable**); volume mode is only the macOS
case-insensitive fallback. Per **ADR-0001**, Linux QEMU runs **in-container with `/dev/kvm`** and
the containerized gdb attaches over TCP.

The detection layer is already complete: `host_profile.detect` resolves `storage_mode`, `accel`
(falls back to `tcg` when `/dev/kvm` is inaccessible), and `debuggee_mode="in-container"` for Linux.
The Build Cache is already storage-mode-aware (`cache.Locations`, `Manifest.storage_mode`). What is
missing — and what B3 delivers — is the **bind wiring**, which is currently un-exercised and
internally inconsistent:

1. **Build/Unpack always mount the named volume**, even in bind mode — the kernel tree never lands
   on the host (so nothing host-editable, contradicting ADR-0002).
2. **`cache.locations()` bind branch is inconsistent**: `kernel_root=/ksrc/<label>` but it maps a
   *single label dir* to `/ksrc` (so `vmlinux` at `/ksrc/vmlinux`), and `image_host=""`.
3. **`cli.run_gdb` hardcodes `storage_mode="volume"`** (the gdb mount source is wrong in bind).
4. **In-container QEMU has no `/dev/kvm` passthrough** — needed for Linux native-arch KVM.
5. **gdbstub topology on Linux is unwired** — two separate containers can't share `localhost`.
6. **`cache.remove_cached` gates bind builds** (raises) and **`require_volume_mode`** blocks everything.

**Scope (decided): full bind runtime, live-gated on the arm64 Ubuntu 26.04 VM for BOTH x86_64 and
arm64 configs** — build → in-container **TCG** boot → containerized gdb at `start_kernel` → systemd
userspace; bind tree host-editable. KVM passthrough ships unit-tested-only (the VM has no `/dev/kvm`).

## 2. Decisions (resolved during grill)

- **Path model = Layout B (parent-dir bind, symmetric container paths).** Bind mode bind-mounts the
  parent host dir `artifacts/ksrc/` at `/ksrc`, exactly mirroring how volume mode mounts the named
  volume at `/ksrc` (label trees as subdirs). Every container-side path becomes **mode-invariant**
  (`kernel_root=/ksrc/<label>`, `vmlinux=/ksrc/<label>/vmlinux`, `image_in_tree=/ksrc/<label>/arch/…`);
  the **only** per-mode difference is the `-v` *source* (volume name ↔ host dir) and whether Export
  runs. Rejected: mounting the single label dir at `/ksrc` (forces a per-mode mount *target*, a second
  axis in the launchers; and is narrower than volume mode's build container, which already sees all labels).
- **Bind tree home = `artifacts/ksrc/<label>`** (host mirror of the `/ksrc` mount). Rejected
  `artifacts/builds/<label>` (the gated code's choice) — clashes with `artifacts/cache/builds/` manifests.
- **`-cpu` model:** arm64 → `host` under `hvf` **or** `kvm` (KVM can only virtualize the host CPU, so a
  forced `cortex-a72` is rejected), `cortex-a72` only under `tcg`. x86_64 → `qemu64[,+smep][,+smap]` in
  **all** accel modes (preserves the ability to present SMEP/SMAP **off** for exploitation; KVM masks
  `qemu64` to host∩model and the toggles still work).
- **KVM passthrough:** `--device /dev/kvm` on the in-container QEMU iff `accel=="kvm"`. Detection guards
  it (no `/dev/kvm` → `accel=tcg` → flag never set). **Unit-tested-only; live-gate deferred** to a real
  KVM host (the Fusion VM exposes no `/dev/kvm`).
- **gdbstub topology = auto per-host, with a `network` override and configurable port** (per the user's
  "most sense per host" steer; see [[feedback-host-appropriate-configurable]]). New domain axis
  **Network mode** (CONTEXT.md): **host** (`--network host`, gdb→`localhost`, Linux default) or
  **published** (`-p`, gdb→`host.docker.internal`, macOS default — and the only option for a native-host
  QEMU). `[debuggee] network = auto|host|published` (`auto`→Linux:host / macOS:published);
  `network=host` is **rejected on macOS** (host-net there is the colima VM, not the Mac).
  `[debuggee] gdb_port = 1234` is threaded everywhere (QEMU uses `-gdb tcp::{port}`, not the fixed `-s`).
  **ADR-0001 is unchanged** — `auto` matches its "localhost/shared-net on Linux, host.docker.internal on
  macOS" exactly.
- **Bind ownership = root build + `chown -R {uid}:{gid} /ksrc/<label>` (bind path only).** Build/unpack
  run as container-root (no risk to the long build from an unknown uid / missing HOME / passwd entry);
  a final chown hands the tree to the host user so it is **host-editable** per ADR-0002 / CONTEXT.md. The
  CLI passes `os.getuid()/getgid()` only when `os=="linux"` and `storage_mode=="bind"` (macOS-bind maps
  ownership via the Docker VM — no chown).
- **No new ADR.** B3 realizes ADR-0002 (bind) and ADR-0001 (topology). CONTEXT.md gains **Network mode**.

## 3. Component design

### 3.1 Config: `gdb_port` + `network` (`src/likedbg/config.py`)

`DebuggeeCfg` gains two fields:
```python
class DebuggeeCfg(_Base):
    ...
    accel: Accel = "auto"
    gdb_port: int = 1234
    network: Network = "auto"   # Network = Literal["auto", "host", "published"]
```
Pydantic lax coercion turns the INI string into `int`/the literal; `extra="forbid"` already guards typos.
(The legacy unused `kvm: bool = False` field is left untouched — `accel` is the live switch; its removal
is out of scope.)

### 3.2 Host profile: resolve **Network mode**, derive `gdbstub_addr` (`src/likedbg/host_profile.py`)

`HostProfile` gains `network_mode: Literal["host", "published"]`; `gdbstub_addr`/`ssh_addr` are
**derived from it** (no longer from `os` directly), so the resolution lives in one place:
```python
NetworkMode = Literal["host", "published"]

@staticmethod
def _resolve_network(requested: str, os_name: str) -> NetworkMode:
    if requested == "host":
        if os_name == "darwin":
            raise HostCapabilityError(
                "network=host is Linux-only (host networking on macOS targets the Docker VM, not the host)",
                remedy="use network=auto or network=published on macOS",
            )
        return "host"
    if requested == "published":
        return "published"
    return "host" if os_name == "linux" else "published"   # auto
```
In `detect`:
```python
network_mode = cls._resolve_network(settings.debuggee.network, os_name)
addr = "localhost" if network_mode == "host" else "host.docker.internal"
return cls(..., network_mode=network_mode, gdbstub_addr=addr, ssh_addr=addr)
```
This keeps every existing axis identical for `auto` (Linux→`localhost`, macOS→`host.docker.internal`,
incl. native-host arm64) — pure refactor + the override. `gdb_port` is **not** on `HostProfile` (it is
config, not a detected capability); stages read `ctx.settings.debuggee.gdb_port`.

### 3.3 Cache locations: Layout B bind branch (`src/likedbg/cache.py`)

```python
TREE_ROOT = "ksrc"   # artifacts/<TREE_ROOT>/<label> mirrors the /ksrc mount

def locations(label, *, arch, storage_mode, workspace, volume=KERNEL_VOLUME) -> Locations:
    image_name = "bzImage" if arch == "x86_64" else "Image"
    container_root = f"{VOLUME_MOUNT}/{label}"                       # /ksrc/<label> — BOTH modes
    image_in_tree = f"{container_root}/arch/{arch}/boot/{image_name}"
    if storage_mode == "volume":
        return Locations(..., image_host=str(workspace/"artifacts"/label/"Image"),
                          gdb_mount_source=volume, gdb_mount_type="volume",
                          gdb_vmlinux=f"{container_root}/vmlinux")
    host_tree = workspace / "artifacts" / TREE_ROOT                 # the PARENT dir, mounted at /ksrc
    return Locations(
        kernel_root=container_root,                                  # /ksrc/<label>  (symmetric)
        vmlinux_in_tree=f"{container_root}/vmlinux",                 # /ksrc/<label>/vmlinux (symmetric)
        image_in_tree=image_in_tree,                                 # container path (symmetric)
        image_host=str(host_tree/label/"arch"/arch/"boot"/image_name),  # REAL host in-tree file
        gdb_mount_source=str(host_tree),                            # artifacts/ksrc, mounted at /ksrc
        gdb_mount_type="bind",
        gdb_vmlinux=f"{container_root}/vmlinux",                     # /ksrc/<label>/vmlinux (symmetric)
    )
```
Key semantics: **`image_host` = the host path of the bootable kernel image** in both modes — the *export
target* in volume mode (populated by the Export stage), the *real in-tree file* in bind mode (populated
by the build itself, no export). `gdb_mount_source` is the kernel tree's location (volume name / host
dir); it is mounted **rw** by Build/Unpack and **ro** by gdb — the same source in both roles.

A tiny helper centralizes that source (so Unpack needs no recipe/arch, and `locations()` reuses it):
```python
def tree_mount_source(workspace: Path, *, storage_mode: str, volume: str = KERNEL_VOLUME) -> str:
    return volume if storage_mode == "volume" else str(workspace / "artifacts" / TREE_ROOT)
```
`locations()` sets `gdb_mount_source = tree_mount_source(workspace, storage_mode=storage_mode, volume=volume)`.

### 3.4 Build / Unpack: per-mode mount source + bind chown (`stages/build.py`, `stages/unpack.py`)

Replace each stage's hardcoded `self._volume` mount source with the shared helper (Build already
computes `loc` for the kernel paths; Unpack uses the helper directly — it has no recipe/arch), ensure
the bind source dir exists, and (build only) chown in bind:
```python
# BuildStage.run / UnpackStage.run — mount the tree (rw), source by mode:
source = cache.tree_mount_source(self._workspace, storage_mode=ctx.host.storage_mode, volume=self._volume)
if ctx.host.storage_mode != "volume":
    Path(source).mkdir(parents=True, exist_ok=True)         # bind: the -v source must exist
volumes = {source: {"bind": VOLUME_MOUNT, "mode": "rw"}, ...}   # target /ksrc in both modes
```
Build, after `make all` (fresh-build branch only), in bind mode, before writing the manifest:
```python
if self._chown_to is not None:                               # (uid, gid) on Linux+bind, else None
    uid, gid = self._chown_to
    self._c.exec(container, f"chown -R {uid}:{gid} {VOLUME_MOUNT}/{label}")
```
`BuildStage.__init__` gains `chown_to: tuple[int, int] | None = None`. Build sets `ctx.kernel_image` to
the **host** path in bind (Export is skipped), the container path in volume (Export overwrites it):
```python
ctx.kernel_image = Path(loc.image_host if ctx.host.storage_mode != "volume" else loc.image_in_tree)
```
The cached-manifest early-return mirrors this from `m.paths` (`image_host` vs `image_in_tree`).
`UnpackStage`'s cached/early paths use `loc.kernel_root` (already `/ksrc/<label>` in both modes). The
volume-mode docker `volumes` dict is byte-identical (source == volume name), so volume mode is unchanged.

### 3.5 Export: unchanged (`stages/export.py`)

`should_skip` already returns `True` when `storage_mode != "volume"`. In bind, Build has already set
`ctx.kernel_image` to the host in-tree path, so the in-container QEMU's identical-path mount resolves.
No change.

### 3.6 Launchers: Network mode + KVM (`src/likedbg/launchers.py`)

`qemu_container_command` gains `network_mode` + `kvm` + honors `gdbstub_port`:
```python
def qemu_container_command(argv, *, image, ro_mounts, rw_mounts, gdbstub_port=1234,
                           network_mode="published", kvm=False) -> str:
    q = shlex.quote
    ro = [f"-v {q(str(p))}:{q(str(p))}:ro" for p in ro_mounts]
    rw = [f"-v {q(str(p))}:{q(str(p))}:rw" for p in rw_mounts]
    net = "--network host" if network_mode == "host" else f"-p {gdbstub_port}:{gdbstub_port}"
    dev = "--device /dev/kvm" if kvm else ""
    docker = f"docker run --rm -it {net} {dev} {' '.join(ro + rw)} {image} "
    return docker + shlex.join(argv)
```
`gdb_pane_command` branches the wrapper on `network_mode` (host-net needs no gateway alias; published
keeps the host-gateway alias B2 lives on):
```python
def gdb_pane_command(gdb_args, *, image, mount_source, network_mode="published") -> str:
    net = "--network host" if network_mode == "host" else "--add-host=host.docker.internal:host-gateway"
    docker = f"docker run --rm -it {net} -v {mount_source}:{VOLUME_MOUNT}:ro {image} "
    return docker + shlex.join(gdb_args)
```
`--network host` and `-p` are mutually exclusive in Docker — the branch picks exactly one. `-v
{mount_source}:/ksrc:ro` works for a volume name *or* a host dir (same `-v` syntax), so `gdb_pane_command`
is otherwise mode-agnostic. (Whitespace from an empty `dev`/empty mounts is cosmetic — already a deferred
B2 minor.)

### 3.7 Stage wiring: thread port / network / kvm (`stages/debuggee.py`, `stages/debugger.py`)

`DebuggeeStage.run` passes the new params from context:
```python
port = ctx.settings.debuggee.gdb_port
kvm = ctx.host.accel == "kvm"
cmd = qemu_container_command(argv, image=self._debuggee_image, ro_mounts=[ctx.kernel_image],
                             rw_mounts=rw_mounts, gdbstub_port=port,
                             network_mode=ctx.host.network_mode, kvm=kvm)
```
`build_qemu_argv` reads `gdb_port` straight off the `settings` it already receives (see §3.8 — no new
param). `DebuggerStage.run` passes `port=ctx.settings.debuggee.gdb_port` to `build_gdb_args`, which uses
it in the `gef-remote {addr} {port}` / `target remote {addr}:{port}` lines (replacing the literal
`1234`). The `run_gdb` closure passes `network_mode` to `gdb_pane_command`.

### 3.8 QEMU argv: configurable port + arm64-KVM cpu (`src/likedbg/qemu.py`)

```python
if arch == "arm64":
    cpu = "host" if host.accel in ("hvf", "kvm") else "cortex-a72"
    argv += ["-M", "virt", "-cpu", cpu]
...
if settings.debuggee.gdb:
    argv += ["-S", "-gdb", f"tcp::{settings.debuggee.gdb_port}"]   # was: -S -s  (-s is fixed :1234)
```
x86_64's `qemu64[,+smep][,+smap]` is unchanged (all accel modes). `-gdb tcp::{port}` is the long form
of `-s` with a configurable port; `-S` (freeze at reset) is unchanged.

### 3.9 CLI: thread storage_mode + host, drop the gate (`src/likedbg/cli.py`)

- `build_pipeline` / `build_use_pipeline` gain a `host: HostProfile` param; the `run_gdb` closure threads
  `storage_mode=host.storage_mode` into `cache.locations(...)` (replacing the hardcoded `"volume"`) and
  `network_mode=host.network_mode` into `gdb_pane_command`.
- The default-run path computes `chown_to = (os.getuid(), os.getgid()) if host.os == "linux" and
  host.storage_mode == "bind" else None` and passes it to `BuildStage`.
- `cmd_use`: set `kernel_image = bm.paths["image_host"] if bm.storage_mode != "volume" else
  bm.paths["image_in_tree"]` (bind needs the host path; `vmlinux`/`gdb_mount_source` already come from
  the manifest and are correct under Layout B). Pass `host` to `build_use_pipeline`.
- **Delete `require_volume_mode`** and both call sites (`main`, `cmd_use`).

### 3.10 Cache removal: bind branch (`src/likedbg/cache.py`)

`remove_cached`'s build branch drops the gate and handles bind with a plain host-tree delete:
```python
if manifest.kind == "build":
    if manifest.storage_mode == "volume":
        ... # existing: BASE_IMAGE container rm -rf /ksrc/<label> + rmtree artifacts/<label>
    else:  # bind: the tree IS on the host
        tree = workspace / "artifacts" / TREE_ROOT / manifest.label
        if tree.is_dir():
            shutil.rmtree(tree)
    manifest_path(...).unlink(missing_ok=True)
```
The whole `/ksrc/<label>` tree was `chown -R`'d to the host user at build time, so `rmtree` runs as
that user with no permission issue (no `ignore_errors` needed).

### 3.11 Adopt: narrow volume-only guard (`src/likedbg/adopt.py` / `cli.py`)

`adopt_legacy_build` migrates the legacy `/ksrc/linux-<version>` **volume** tree; it is meaningless in
bind mode. With `require_volume_mode` gone, add a narrow explicit guard so `--adopt` on Linux fails
clearly instead of confusingly hunting an empty volume. Cleanest: detect the host in the `--adopt` branch
and raise if `storage_mode != "volume"`:
```python
raise HostCapabilityError("--adopt migrates the legacy volume tree and is volume-mode only",
                          remedy="bind/Linux builds fresh — just run start_kgdb")
```

## 4. Regression safety (macOS volume mode unchanged)

Volume mode is the live-gated path and must not move. Guarantees: `locations()` volume branch is
byte-identical; Build/Unpack volume `volumes` dict is identical (`gdb_mount_source == volume`); Export
runs in volume only; no chown in volume / non-Linux; `gdbstub_addr` for every `auto` host is identical
(Linux→`localhost`, macOS→`host.docker.internal`, native-host arm64→`host.docker.internal`); the
launchers default `network_mode="published"`, `kvm=False` (B2 behavior). `gdb_port` defaults to `1234`,
so `-gdb tcp::1234` is wire-equivalent to the old `-s`. The 164-test suite stays green; new behavior is
gated on `storage_mode=="bind"` / `network_mode=="host"` / `accel=="kvm"`.

## 5. Testing strategy

Unit (in `./tests/`), TDD per change:
- `config`: `[debuggee]` accepts `gdb_port`/`network`; bad `network` value rejected (`extra`/literal).
- `host_profile._resolve_network`: auto→linux:`host`/darwin:`published`; explicit `host` on darwin
  **raises**; explicit `published` everywhere; `gdbstub_addr` derives (`host`→localhost,
  `published`→host.docker.internal); native-host arm64 (auto, darwin) → `published`/host.docker.internal.
- `cache.locations` bind: `kernel_root`/`vmlinux`/`image_in_tree` symmetric with volume; `image_host`
  is the host in-tree path (`artifacts/ksrc/<label>/arch/<arch>/boot/<bzImage|Image>`);
  `gdb_mount_source==artifacts/ksrc`, `gdb_mount_type=="bind"`; volume branch unchanged (regression).
- `BuildStage`/`UnpackStage`: bind → mount source is `artifacts/ksrc` (rw) at `/ksrc`, source dir
  created; volume → source is the volume name (regression); bind fresh-build emits
  `chown -R {uid}:{gid} /ksrc/<label>` (fake container records exec'd cmds), volume emits none;
  `ctx.kernel_image` is `image_host` (bind) vs `image_in_tree` (volume) on both fresh and cached paths.
- `qemu_container_command`: `network_mode="host"` → `--network host`, **no** `-p`; `"published"` →
  `-p {port}:{port}`, no `--network host`; `kvm=True` → `--device /dev/kvm`, `kvm=False` → absent;
  ro/rw identical-path binds; custom `gdbstub_port`.
- `gdb_pane_command`: `host` → `--network host` (no host-gateway alias); `published` → host-gateway alias.
- `build_qemu_argv`: `-gdb tcp::{port}` with default and custom port; arm64 `accel="kvm"` → `-cpu host`,
  `accel="tcg"` → `cortex-a72`, `accel="hvf"` → `host` (regression); x86_64 `qemu64,+smep,+smap`
  unchanged under every accel; `gdb=False` → no `-S`/`-gdb`.
- `build_gdb_args`: `gef-remote {addr} {port}` / `target remote {addr}:{port}` honor a custom port.
- `cache.remove_cached`: bind build → `rmtree(artifacts/ksrc/<label>)`, no container, manifest unlinked;
  volume build unchanged (regression); rootfs branch unchanged.
- `cli`: `require_volume_mode` gone (delete its tests); `run_gdb` threads `storage_mode`/`network_mode`;
  `cmd_use` picks `image_host` in bind; `--adopt` on a bind host raises the volume-only error.
- Gate: `uv run ruff check src tests`, `ruff format --check`, `uv run mypy src/likedbg`,
  `uv run pytest -q` all green.

## 6. Live-gate verification (arm64 Ubuntu 26.04 VM)

Environment (probed 2026-06-24): arm64, Docker 29.6.0 (`pwn` in `docker` group), **no `/dev/kvm`**
(→ both arches run in-container **TCG**), host `qemu-x86_64` binfmt **registered** (foreign-arch rootfs
de-risked), 4 cores / 7.2 GiB / 21 GiB free. Prep: install `uv` (only hard gap; git/rsync/tmux/python
present). Rsync the repo over; `uv run ./start_kgdb --build-images` (5 images).

1. **x86_64 config** (`[general] arch=x86_64`): `uv run ./start_kgdb` → cross-compiled x86_64 kernel,
   **foreign-arch amd64 rootfs**, in-container **TCG** boot, containerized gdb `hbreak start_kernel`
   (source-level), `continue` → **systemd userspace** login; runtime breakpoint on the live kernel.
2. **arm64 config** (`[general] arch=arm64`): same end-to-end, in-container **TCG** (no KVM here).
3. **Bind asserts:** the kernel tree is at `artifacts/ksrc/<label>/`, **owned by `pwn`** (editable, no
   sudo); `--list`/`--clean <label>` work (bind removal = host rmtree); no leftover helper containers.
4. **Topology branches:** default `network=auto`→`host` (gdb→`localhost`); additionally force
   `network=published` and a non-default `gdb_port` on Linux to exercise those branches live.
5. **macOS no-regression:** an arm64 volume-mode run on the M5 still build→boot→debugs via native-HVF
   exactly as before (covered by the suite; spot-checked live).

## 7. Non-goals

- **KVM live-gate:** `--device /dev/kvm` ships implemented + unit-tested; its *live* verification is
  deferred to a real KVM host (nested-virt-capable setup). Detection guards it on no-KVM hosts.
- **Cross-arch on a physical x64 Linux box:** the ROADMAP's "build arm64 on x64 Linux" cross-check is a
  later, separate live gate; B3's design supports it (TCG foreign-arch), but it is not gated here.
- **macOS-bind as a first-class path:** the bind code is OS-agnostic, so a macOS power-user override
  (`mac_storage=bind` on a case-sensitive volume) works through the same path and is unit-tested via
  `host_profile`; it is **not** separately live-gated (no case-sensitive Mac volume on hand, no chown there).
- **`--use` in-container parity / `USE_IMAGES`:** unchanged from B2 scope; bind `--use` rides the same
  manifest paths but is not a B3 deliverable beyond the `image_host` fix.
- **§C cache niceties** (`--use` rootfs build-if-absent, in-volume size, `--adopt-rootfs`): out of scope.
- **Legacy `DebuggeeCfg.kvm` field removal** and the `like_kbuilder_arm64` misnomer: deferred (ROADMAP).
- **TCG performance:** boots are slow by nature on the VM; not optimized here.

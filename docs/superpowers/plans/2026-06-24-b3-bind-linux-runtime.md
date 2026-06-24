# B3 — Bind/Linux Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un-gate the bind storage runtime so the like-dbg daily-driver builds, boots, and debugs on Linux (both x86_64 and arm64 configs), with the kernel tree host-editable, while macOS volume mode stays byte-for-byte unchanged.

**Architecture:** Layout B — bind mode bind-mounts the parent host dir `artifacts/ksrc/` at `/ksrc`, mirroring how volume mode mounts the named volume, so every container-side path is mode-invariant and only the `-v` *source* differs. Topology is auto-per-host (Linux `--network host`+`localhost`, macOS `-p`+`host.docker.internal`) via a new **Network mode** axis, with a `network` override and configurable `gdb_port`. KVM passthrough (`--device /dev/kvm`) is wired but only fires when detection sees `/dev/kvm`.

**Tech Stack:** Python 3.12 (managed by `uv`), pydantic v2 settings, Docker SDK via `ContainerService`, pytest. Pure-function stages + injected callables (no `main()` in the unit suite).

## Global Constraints

- **`dev` stays local — never `git push`.** This work lands on branch `feat/b3-bind-linux` off `dev`, merged **locally**.
- **No new runtime dependencies.**
- **macOS volume mode must stay byte-identical** (it is the live-gated path) — every new behavior is gated on `storage_mode=="bind"` / `network_mode=="host"` / `accel=="kvm"`. The existing suite stays green.
- **All container-side paths are mode-invariant** (`kernel_root=/ksrc/<label>`, `vmlinux=/ksrc/<label>/vmlinux`).
- **Per-task gate (run before each commit):** `uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src/likedbg && uv run pytest -q` — all green.
- **Spec:** `docs/superpowers/specs/2026-06-24-b3-bind-linux-runtime-design.md`. **Glossary:** `CONTEXT.md` (Network mode, Storage mode). **Decisions:** ADR-0001 (topology, unchanged), ADR-0002 (bind mode).
- **Add a field to the frozen `HostProfile` only as a trailing field with a default** (`network_mode: NetworkMode = "published"`) so the ~5 hand-built constructors in tests keep working.

---

### Task 1: Config — `gdb_port` + `network`

**Files:**
- Modify: `src/likedbg/config.py` (add `Network` literal; two `DebuggeeCfg` fields)
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `settings.debuggee.gdb_port: int` (default `1234`), `settings.debuggee.network: str` (`"auto"|"host"|"published"`, default `"auto"`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_config.py`:
```python
def test_gdb_port_and_network_defaults():
    s = _load()
    assert s.debuggee.gdb_port == 1234
    assert s.debuggee.network == "auto"


def test_gdb_port_and_network_overrides(tmp_path):
    custom = tmp_path / "custom.ini"
    custom.write_text("[debuggee]\ngdb_port = 4444\nnetwork = published\n")
    s = _load(custom_ini=custom)
    assert s.debuggee.gdb_port == 4444
    assert s.debuggee.network == "published"


def test_invalid_network_raises_configerror(tmp_path):
    custom = tmp_path / "custom.ini"
    custom.write_text("[debuggee]\nnetwork = bridge\n")
    with pytest.raises(ConfigError):
        _load(custom_ini=custom)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_config.py -q`
Expected: FAIL (`gdb_port`/`network` are unknown — `extra="forbid"` raises, or attr missing).

- [ ] **Step 3: Implement**

In `src/likedbg/config.py`, add the literal near the others (after `Ext`):
```python
Network = Literal["auto", "host", "published"]
```
Add two fields to `DebuggeeCfg` (after `accel`):
```python
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
    gdb_port: int = 1234
    network: Network = "auto"
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_config.py -q`
Expected: PASS (all config tests).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/config.py tests/test_config.py
git commit -m "feat(config): gdb_port + network knobs in [debuggee]"
```

---

### Task 2: Host profile — resolve **Network mode**, derive gdbstub addr

**Files:**
- Modify: `src/likedbg/host_profile.py` (`NetworkMode` type; `network_mode` field; `_resolve_network`; derive `addr`; set field in `detect`)
- Test: `tests/test_host_profile.py`

**Interfaces:**
- Consumes: `settings.debuggee.network` (Task 1).
- Produces: `HostProfile.network_mode: Literal["host","published"]`; `gdbstub_addr`/`ssh_addr` derived from it (`host`→`localhost`, `published`→`host.docker.internal`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_host_profile.py`:
```python
def test_network_auto_linux_is_host_and_localhost():
    p = _probes(system="linux", machine="arm64", kvm=False)
    hp = HostProfile.detect(_settings("arm64"), Path("/ws"), p)
    assert hp.network_mode == "host"
    assert hp.gdbstub_addr == "localhost" and hp.ssh_addr == "localhost"


def test_network_auto_mac_is_published_and_host_docker_internal():
    p = _probes(system="darwin", machine="arm64", hvf=True, qemu=True)
    hp = HostProfile.detect(_settings("arm64"), Path("/ws"), p)
    assert hp.network_mode == "published"
    assert hp.gdbstub_addr == "host.docker.internal"


def test_network_published_override_on_linux():
    p = _probes(system="linux", machine="arm64", kvm=False)
    s = Settings.model_validate({"general": {"arch": "arm64"}, "debuggee": {"network": "published"}})
    hp = HostProfile.detect(s, Path("/ws"), p)
    assert hp.network_mode == "published" and hp.gdbstub_addr == "host.docker.internal"


def test_network_host_on_mac_raises():
    p = _probes(system="darwin", machine="arm64", hvf=True, qemu=True)
    s = Settings.model_validate({"general": {"arch": "arm64"}, "debuggee": {"network": "host"}})
    with pytest.raises(HostCapabilityError):
        HostProfile.detect(s, Path("/ws"), p)
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_host_profile.py -q`
Expected: FAIL (`network_mode` attribute missing; `detect` ignores `network`).

- [ ] **Step 3: Implement**

In `src/likedbg/host_profile.py`:

Add the type alias (after `StorageMode`):
```python
NetworkMode = Literal["host", "published"]
```
Add a trailing field with a default to the dataclass (so existing constructors keep working):
```python
@dataclass(frozen=True)
class HostProfile:
    os: str
    host_arch: str
    accel: Accel
    debuggee_mode: DebuggeeMode
    storage_mode: StorageMode
    gdbstub_addr: str
    ssh_addr: str
    network_mode: NetworkMode = "published"
```
Add the resolver (a `@staticmethod`, beside `_resolve_storage`):
```python
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
    return "host" if os_name == "linux" else "published"  # auto
```
In `detect`, replace the `addr = ...` line + the `return cls(...)` so `addr` derives from `network_mode`:
```python
        network_mode = cls._resolve_network(settings.debuggee.network, os_name)
        # gdb is always containerized; it reaches QEMU on localhost (host networking, Linux)
        # or via the Docker gateway host.docker.internal (published port, macOS / native-host).
        addr = "localhost" if network_mode == "host" else "host.docker.internal"
        return cls(
            os=os_name,
            host_arch=host_arch,
            accel=accel,
            debuggee_mode=mode,
            storage_mode=storage,
            gdbstub_addr=addr,
            ssh_addr=addr,
            network_mode=network_mode,
        )
```

- [ ] **Step 4: Run to verify they pass (and existing host_profile tests stay green)**

Run: `uv run pytest tests/test_host_profile.py -q`
Expected: PASS. (Existing `test_linux_same_arch_with_kvm` → auto/linux → `host` → `localhost`; `test_x86_on_arm_mac_*` → auto/darwin → `published` → `host.docker.internal`.)

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/host_profile.py tests/test_host_profile.py
git commit -m "feat(host_profile): resolve Network mode; derive gdbstub addr from it"
```

---

### Task 3: Cache — `TREE_ROOT`, `tree_mount_source`, Layout B bind locations

**Files:**
- Modify: `src/likedbg/cache.py` (`TREE_ROOT` const; `tree_mount_source` helper; rewrite bind branch of `locations`)
- Test: `tests/test_cache_locations.py` (update the bind footprint test; add helper test)

**Interfaces:**
- Produces: `cache.TREE_ROOT = "ksrc"`; `cache.tree_mount_source(workspace: Path, *, storage_mode: str, volume: str = KERNEL_VOLUME) -> str`; Layout-B `Locations` for bind (`image_host` = host in-tree image path, `gdb_mount_source` = `<ws>/artifacts/ksrc`, `gdb_mount_type="bind"`, `gdb_vmlinux=/ksrc/<label>/vmlinux`, `kernel_root`/`vmlinux_in_tree`/`image_in_tree` symmetric with volume).

- [ ] **Step 1: Replace the bind footprint test + add the helper test**

In `tests/test_cache_locations.py`, **replace** `test_bind_mode_footprint_has_no_host_export` with:
```python
def test_bind_mode_footprint_is_symmetric_and_host_in_tree():
    from likedbg.cache import tree_mount_source

    label = "linux-6.6.30-gef-a1b2c3d4"
    loc = locations(label, arch="x86_64", storage_mode="bind", workspace=Path("/ws"))
    # container-side paths are identical to volume mode (mode-invariant)
    assert loc.kernel_root == f"/ksrc/{label}"
    assert loc.image_in_tree == f"/ksrc/{label}/arch/x86_64/boot/bzImage"
    assert loc.gdb_vmlinux == f"/ksrc/{label}/vmlinux"
    # image_host is the REAL host in-tree file (no export step in bind)
    assert loc.image_host == f"/ws/artifacts/ksrc/{label}/arch/x86_64/boot/bzImage"
    # the tree's mount source is the parent ksrc dir, mounted at /ksrc
    assert loc.gdb_mount_source == "/ws/artifacts/ksrc"
    assert loc.gdb_mount_type == "bind"
    # the helper returns the same source (used rw by build/unpack, ro by gdb)
    assert tree_mount_source(Path("/ws"), storage_mode="bind") == "/ws/artifacts/ksrc"
    assert tree_mount_source(Path("/ws"), storage_mode="volume") == "likedbg_ksrc"
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_cache_locations.py -q`
Expected: FAIL (`tree_mount_source` undefined; bind `image_host` is `""`, `gdb_mount_source` is the old `builds/...` path).

- [ ] **Step 3: Implement**

In `src/likedbg/cache.py`, add the constant near the top (after the imports / `_SLUG_RE`):
```python
TREE_ROOT = "ksrc"  # host mirror of the /ksrc mount: artifacts/<TREE_ROOT>/<label>
```
Add the helper (just above `locations`):
```python
def tree_mount_source(workspace: Path, *, storage_mode: str, volume: str = KERNEL_VOLUME) -> str:
    """The kernel tree's mount source — the named volume (volume mode) or the host
    artifacts/ksrc dir (bind mode). Mounted at VOLUME_MOUNT (/ksrc) rw by Build/Unpack, ro by gdb."""
    return volume if storage_mode == "volume" else str(workspace / "artifacts" / TREE_ROOT)
```
Rewrite the **bind branch** of `locations` (the block after the `if storage_mode == "volume":` return). Replace lines from `host_tree = workspace / "artifacts" / "builds" / label` through the final `return Locations(...)` with:
```python
    host_tree = workspace / "artifacts" / TREE_ROOT / label  # the real on-host kernel tree (bind)
    return Locations(
        kernel_root=container_root,                       # /ksrc/<label>  (symmetric with volume)
        vmlinux_in_tree=f"{container_root}/vmlinux",
        image_in_tree=image_in_tree,                      # container path (symmetric)
        image_host=str(host_tree / "arch" / arch / "boot" / image_name),  # real host in-tree file
        gdb_mount_source=tree_mount_source(workspace, storage_mode=storage_mode, volume=volume),
        gdb_mount_type="bind",
        gdb_vmlinux=f"{container_root}/vmlinux",           # /ksrc/<label>/vmlinux (symmetric)
    )
```
Also make the **volume branch** use the helper for its `gdb_mount_source` (keeps one source of truth; value is unchanged — the volume name):
```python
        gdb_mount_source=tree_mount_source(workspace, storage_mode=storage_mode, volume=volume),
```

- [ ] **Step 4: Run to verify it passes (volume + x86 tests stay green)**

Run: `uv run pytest tests/test_cache_locations.py -q`
Expected: PASS (`test_volume_mode_footprint`, `test_x86_uses_bzimage`, and the new bind test).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_locations.py
git commit -m "feat(cache): Layout B bind locations + tree_mount_source helper"
```

---

### Task 4: Cache — bind-mode removal

**Files:**
- Modify: `src/likedbg/cache.py` (`remove_cached` build branch: bind = host rmtree, drop the gate)
- Test: `tests/test_cache_remove.py` (replace the "refuses bind" test)

**Interfaces:**
- Consumes: `cache.TREE_ROOT` (Task 3).

- [ ] **Step 1: Replace the gate test with a bind-removal test**

In `tests/test_cache_remove.py`, **replace** `test_remove_build_refuses_non_volume_storage` with:
```python
def test_remove_bind_build_rmtrees_host_tree(tmp_path):
    label = "linux-6.6.30-bbbb"
    tree = tmp_path / "artifacts" / "ksrc" / label / "arch" / "arm64" / "boot"
    tree.mkdir(parents=True)
    (tree / "Image").write_bytes(b"img")
    m = Manifest(kind="build", label=label, key="k", version="6.6.30", arch="arm64", storage_mode="bind")
    write_manifest(tmp_path, m)
    c = FakeC()
    remove_cached(c, tmp_path, m)
    assert c.execs == []  # bind tree is on the host; no container needed
    assert not (tmp_path / "artifacts" / "ksrc" / label).exists()
    assert manifest_exists(tmp_path, "build", label) is False
```
(`CacheError` is no longer raised here; the `pytest`/`CacheError` imports stay — other tests use them.)

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_cache_remove.py -q`
Expected: FAIL (current code raises `CacheError` for bind).

- [ ] **Step 3: Implement**

In `src/likedbg/cache.py`, replace the build branch of `remove_cached` (the `if manifest.kind == "build":` block up to its `else:`) with:
```python
    if manifest.kind == "build":
        if manifest.storage_mode == "volume":
            c = container.run_detached(
                BASE_IMAGE, volumes={volume: {"bind": VOLUME_MOUNT, "mode": "rw"}}, detach=True, tty=True
            )
            try:
                container.exec(c, f"rm -rf {VOLUME_MOUNT}/{manifest.label}")
            finally:
                container.stop(c)
            export_dir = workspace / "artifacts" / manifest.label
            if export_dir.is_dir():
                shutil.rmtree(export_dir)
        else:  # bind: the tree IS on the host — chown'd to the user at build time, so rmtree just works
            tree = workspace / "artifacts" / TREE_ROOT / manifest.label
            if tree.is_dir():
                shutil.rmtree(tree)
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/test_cache_remove.py -q`
Expected: PASS (volume removal + rootfs removal regressions + the new bind test).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cache.py tests/test_cache_remove.py
git commit -m "feat(cache): bind-mode build removal (host rmtree); drop the volume gate"
```

---

### Task 5: QEMU argv — configurable gdb port + arm64-KVM `-cpu host`

**Files:**
- Modify: `src/likedbg/qemu.py` (`-gdb tcp::{port}` instead of `-s`; arm64 `-cpu host` under `kvm`)
- Test: `tests/test_qemu.py` (update the `-s` assertion; add port + cpu tests)

**Interfaces:**
- Consumes: `settings.debuggee.gdb_port` (Task 1), `host.accel`.
- Produces: argv tail `-S -gdb tcp::{port}` when `gdb` enabled.

- [ ] **Step 1: Update the gdbstub-flags test + add port and cpu tests**

In `tests/test_qemu.py`, **replace** `test_gdbstub_flags_present_when_gdb_enabled` with:
```python
def test_gdbstub_flags_present_when_gdb_enabled():
    argv = build_qemu_argv(_settings("arm64", gdb=True), _host(), kernel_image=Path("/w/Image"), rootfs=None)
    assert "-S" in argv
    assert "-gdb" in argv and "tcp::1234" in argv
    assert "-s" not in argv  # replaced by the explicit -gdb form


def test_gdb_port_is_configurable():
    argv = build_qemu_argv(_settings("arm64", gdb=True, gdb_port=4444), _host(), kernel_image=Path("/w/Image"), rootfs=None)
    assert "tcp::4444" in argv
```
Add CPU-model tests (the `_host()` helper takes an accel via `_host("kvm")` etc.):
```python
def test_arm64_kvm_uses_cpu_host():
    argv = build_qemu_argv(_settings("arm64"), _host("kvm", "in-container"), kernel_image=Path("/w/Image"), rootfs=None)
    assert "-cpu host" in _argstr(argv)


def test_arm64_tcg_uses_cortex_a72():
    argv = build_qemu_argv(_settings("arm64"), _host("tcg", "in-container"), kernel_image=Path("/w/Image"), rootfs=None)
    assert "-cpu cortex-a72" in _argstr(argv)


def test_x86_64_keeps_qemu64_features_under_kvm():
    argv = build_qemu_argv(_settings("x86_64"), _host("kvm", "in-container"), kernel_image=Path("/w/Image"), rootfs=None)
    s = _argstr(argv)
    assert "qemu64" in s and "+smep" in s and "+smap" in s  # toggles preserved even under KVM
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_qemu.py -q`
Expected: FAIL (`-s` still emitted; arm64 always `cortex-a72`).

- [ ] **Step 3: Implement**

In `src/likedbg/qemu.py`, in `build_qemu_argv`, change the arm64 CPU choice:
```python
    if arch == "arm64":
        cpu = "host" if host.accel in ("hvf", "kvm") else "cortex-a72"
        argv += ["-M", "virt", "-cpu", cpu]
        console = "console=ttyAMA0"
```
Change the gdbstub flags (the `if settings.debuggee.gdb:` block at the end):
```python
    if settings.debuggee.gdb:
        argv += ["-S", "-gdb", f"tcp::{settings.debuggee.gdb_port}"]
```
(x86_64's `qemu64[,+smep][,+smap]` block is unchanged.)

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/test_qemu.py -q`
Expected: PASS (incl. regressions: hvf→`-cpu host`, x86 features, append/rootfs tests).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/qemu.py tests/test_qemu.py
git commit -m "feat(qemu): configurable -gdb tcp::PORT; arm64 -cpu host under KVM"
```

---

### Task 6: gdbcmd — configurable port in the remote target

**Files:**
- Modify: `src/likedbg/gdbcmd.py` (`build_gdb_args(..., port: int = 1234)`)
- Test: `tests/test_gdbcmd.py` (add a custom-port test)

**Interfaces:**
- Produces: `build_gdb_args(host, *, arch, vmlinux, ext, breakpoint, port=1234)` — `gef-remote {addr} {port}` / `target remote {addr}:{port}`.

- [ ] **Step 1: Add the failing test**

Append to `tests/test_gdbcmd.py`:
```python
def test_remote_port_is_configurable():
    gef = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="gef", breakpoint=None, port=4444)
    assert "gef-remote host.docker.internal 4444" in " ".join(gef)
    pdb = build_gdb_args(_host(), arch="arm64", vmlinux=Path("/w/vmlinux"), ext="pwndbg", breakpoint=None, port=4444)
    assert "target remote host.docker.internal:4444" in " ".join(pdb)
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_gdbcmd.py -q`
Expected: FAIL (`build_gdb_args` has no `port` parameter).

- [ ] **Step 3: Implement**

In `src/likedbg/gdbcmd.py`, add the keyword and use it:
```python
def build_gdb_args(
    host: HostProfile, *, arch: str, vmlinux: Path, ext: str, breakpoint: str | None, port: int = 1234
) -> list[str]:
    ...
    if ext == "gef":
        args += ["-ex", f"gef-remote {addr} {port}"]
    else:
        args += ["-ex", f"target remote {addr}:{port}"]
```

- [ ] **Step 4: Run to verify it passes (default 1234 keeps existing tests green)**

Run: `uv run pytest tests/test_gdbcmd.py -q`
Expected: PASS (existing tests use the `1234` default).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/gdbcmd.py tests/test_gdbcmd.py
git commit -m "feat(gdbcmd): configurable gdbstub port in the remote target"
```

---

### Task 7: Launchers — Network mode + KVM passthrough

**Files:**
- Modify: `src/likedbg/launchers.py` (`qemu_container_command` gains `network_mode`/`kvm`; `gdb_pane_command` gains `network_mode`)
- Test: `tests/test_launchers.py`

**Interfaces:**
- Produces: `qemu_container_command(argv, *, image, ro_mounts, rw_mounts, gdbstub_port=1234, network_mode="published", kvm=False)`; `gdb_pane_command(gdb_args, *, image, mount_source, network_mode="published")`.

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_launchers.py`:
```python
def test_qemu_container_host_network_omits_published_port():
    cmd = qemu_container_command(
        ["qemu-system-aarch64", "-kernel", "/w/Image"],
        image="like_debuggee:latest", ro_mounts=[Path("/w/Image")], rw_mounts=[], network_mode="host",
    )
    assert "--network host" in cmd
    assert "-p 1234:1234" not in cmd  # host net and -p are mutually exclusive


def test_qemu_container_kvm_passes_device():
    cmd = qemu_container_command(
        ["qemu-system-aarch64", "-kernel", "/w/Image"],
        image="like_debuggee:latest", ro_mounts=[Path("/w/Image")], rw_mounts=[],
        network_mode="host", kvm=True,
    )
    assert "--device /dev/kvm" in cmd


def test_qemu_container_no_kvm_omits_device():
    cmd = qemu_container_command(
        ["qemu-system-aarch64", "-kernel", "/w/Image"],
        image="like_debuggee:latest", ro_mounts=[Path("/w/Image")], rw_mounts=[],
    )
    assert "/dev/kvm" not in cmd


def test_gdb_pane_host_network_uses_localhost_path_not_gateway():
    cmd = gdb_pane_command(["gdb-multiarch"], image="img", mount_source="/ws/artifacts/ksrc", network_mode="host")
    assert "--network host" in cmd
    assert "--add-host=host.docker.internal:host-gateway" not in cmd
    assert "-v /ws/artifacts/ksrc:/ksrc:ro" in cmd
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_launchers.py -q`
Expected: FAIL (`network_mode`/`kvm` are unexpected keyword args).

- [ ] **Step 3: Implement**

In `src/likedbg/launchers.py`, rewrite `qemu_container_command`:
```python
def qemu_container_command(
    argv: list[str], *, image: str, ro_mounts: list[Path], rw_mounts: list[Path],
    gdbstub_port: int = 1234, network_mode: str = "published", kvm: bool = False,
) -> str:
    # In-container QEMU. Bind each artifact at its identical host path so the argv's embedded
    # paths resolve unchanged (kernel :ro, rootfs disk :rw). Network mode: host net (Linux,
    # gdb→localhost) or a published gdbstub port (macOS / forced, gdb→host.docker.internal).
    q = shlex.quote
    ro = [f"-v {q(str(p))}:{q(str(p))}:ro" for p in ro_mounts]
    rw = [f"-v {q(str(p))}:{q(str(p))}:rw" for p in rw_mounts]
    binds = " ".join(ro + rw)
    net = "--network host" if network_mode == "host" else f"-p {gdbstub_port}:{gdbstub_port}"
    dev = " --device /dev/kvm" if kvm else ""
    docker = f"docker run --rm -it {net}{dev} {binds} {image} "
    return docker + shlex.join(argv)
```
Rewrite `gdb_pane_command`:
```python
def gdb_pane_command(gdb_args: list[str], *, image: str, mount_source: str, network_mode: str = "published") -> str:
    # Host net (Linux): gdb reaches QEMU on localhost. Published (macOS): the host-gateway alias
    # resolves host.docker.internal to the published gdbstub port.
    net = "--network host" if network_mode == "host" else "--add-host=host.docker.internal:host-gateway"
    docker = f"docker run --rm -it {net} -v {mount_source}:{VOLUME_MOUNT}:ro {image} "
    return docker + shlex.join(gdb_args)
```

- [ ] **Step 4: Run to verify they pass (published defaults keep B2 tests green)**

Run: `uv run pytest tests/test_launchers.py -q`
Expected: PASS (existing `-p 1234:1234` / `--add-host` tests use the `published` defaults).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/launchers.py tests/test_launchers.py
git commit -m "feat(launchers): Network mode branch (host net vs published) + /dev/kvm passthrough"
```

---

### Task 8: Stages — Build/Unpack bind wiring (host tree + chown + host image path)

**Files:**
- Modify: `src/likedbg/stages/unpack.py` (mount source via helper; mkdir bind source)
- Modify: `src/likedbg/stages/build.py` (mount source via helper; mkdir bind source; `chown_to` param + bind chown; `ctx.kernel_image` = host image in bind, both fresh + cached)
- Test: `tests/test_stage_unpack.py`, `tests/test_stage_build.py`

**Interfaces:**
- Consumes: `cache.tree_mount_source` (Task 3), `loc.image_host`, `host.storage_mode`.
- Produces: `BuildStage(..., chown_to: tuple[int, int] | None = None)`; in bind, `ctx.kernel_image` is the host in-tree image path.

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_stage_unpack.py`:
```python
def test_bind_mode_mounts_host_ksrc_dir(tmp_path):
    svc = FakeContainerService()
    UnpackStage(svc, kernel_volume="likedbg_ksrc", workspace=tmp_path).run(_ctx("bind", tmp_path))
    mounts = str(svc.run_kwargs["volumes"])
    assert str(tmp_path / "artifacts" / "ksrc") in mounts
    assert "likedbg_ksrc" not in mounts
    assert (tmp_path / "artifacts" / "ksrc").is_dir()  # bind source created
```
Append to `tests/test_stage_build.py`:
```python
def test_build_bind_mode_mounts_host_ksrc_and_chowns(tmp_path):
    c = _BuildFakeC()
    label = "linux-6.6.30-a1b2c3d4"
    ctx = _ctx(tmp_path, storage="bind")
    ctx.build_label = label
    ctx.kernel_root = None
    BuildStage(
        c, recipe=_recipe(), kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path, kernel_volume="likedbg_ksrc", chown_to=(1000, 1000),
    ).run(ctx)
    vols = str(c.run_kwargs["volumes"])
    assert str(tmp_path / "artifacts" / "ksrc") in vols and "likedbg_ksrc" not in vols
    assert any(f"chown -R 1000:1000 /ksrc/{label}" in e for e in c.execs)
    # in bind, the in-container QEMU needs the HOST image path
    assert str(ctx.kernel_image) == str(tmp_path / "artifacts" / "ksrc" / label / "arch" / "arm64" / "boot" / "Image")


def test_build_volume_mode_does_not_chown(tmp_path):
    c = _BuildFakeC()
    ctx = _ctx(tmp_path, storage="volume")
    ctx.build_label = "linux-6.6.30-a1b2c3d4"
    ctx.kernel_root = None
    BuildStage(
        c, recipe=_recipe(), kbuilder_image="like_kbuilder_arm64:latest",
        workspace=tmp_path, kernel_volume="likedbg_ksrc", chown_to=(1000, 1000),
    ).run(ctx)
    assert all("chown" not in e for e in c.execs)  # chown is bind-only
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_stage_unpack.py tests/test_stage_build.py -q`
Expected: FAIL (volume always mounted; `chown_to` unknown kwarg; bind `kernel_image` is a container path).

- [ ] **Step 3: Implement**

In `src/likedbg/stages/unpack.py`, in `run()`, replace the `volumes = { self._volume: ... }` construction (the miss path) with a per-mode source:
```python
        source = cache.tree_mount_source(self._workspace, storage_mode=ctx.host.storage_mode, volume=self._volume)
        if ctx.host.storage_mode != "volume":
            Path(source).mkdir(parents=True, exist_ok=True)
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            source: {"bind": VOLUME_MOUNT, "mode": "rw"},
        }
```
In `src/likedbg/stages/build.py`:

Add `chown_to` to `__init__` and store it:
```python
    def __init__(self, container, *, recipe, kbuilder_image, workspace, kernel_volume, chown_to=None):
        ...
        self._chown_to = chown_to
```
In `run()`, change the volume source (the `volumes = {...}` in the build path):
```python
        source = cache.tree_mount_source(self._workspace, storage_mode=ctx.host.storage_mode, volume=self._volume)
        if ctx.host.storage_mode != "volume":
            Path(source).mkdir(parents=True, exist_ok=True)
        volumes = {
            str(self._workspace): {"bind": _MOUNT, "mode": "ro"},
            source: {"bind": VOLUME_MOUNT, "mode": "rw"},
        }
```
Add the bind chown as the **last `exec` inside the `try:` block** — immediately after the `make all` exec and *before* the `finally: self._c.stop(container)` (the container must still be alive):
```python
            self._c.exec(container, make_command(env, "all"), workdir=root)
            if self._chown_to is not None and ctx.host.storage_mode != "volume":
                uid, gid = self._chown_to
                self._c.exec(container, f"chown -R {uid}:{gid} {VOLUME_MOUNT}/{label}", workdir=root)
        finally:
            self._c.stop(container)
```
Then (after the `finally`, outside the try) set `ctx.kernel_image` per mode:
Change the two `ctx.kernel_image = ...` assignments to be mode-aware. Fresh-build branch:
```python
        ctx.vmlinux = Path(loc.vmlinux_in_tree)
        ctx.kernel_image = Path(loc.image_host if ctx.host.storage_mode != "volume" else loc.image_in_tree)
```
Cached-manifest branch (the early return):
```python
            ctx.vmlinux = Path(m.paths["vmlinux_in_tree"])
            img = m.paths["image_host"] if m.storage_mode != "volume" else m.paths["image_in_tree"]
            ctx.kernel_image = Path(img)
            return ctx
```
(`cache` is already imported in both stages; `Path` already imported.)

- [ ] **Step 4: Run to verify they pass (volume regressions stay green)**

Run: `uv run pytest tests/test_stage_unpack.py tests/test_stage_build.py -q`
Expected: PASS (incl. `test_build_volume_mode_mounts_named_volume_and_workspace`, `test_build_sets_vmlinux_and_image_paths`, the cached-reuse test).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/unpack.py src/likedbg/stages/build.py tests/test_stage_unpack.py tests/test_stage_build.py
git commit -m "feat(stages): bind build/unpack to host artifacts/ksrc; chown tree; host image path"
```

---

### Task 9: Stages — thread port / network / kvm into Debuggee & Debugger

**Files:**
- Modify: `src/likedbg/stages/debuggee.py` (pass `gdbstub_port`, `network_mode`, `kvm`)
- Modify: `src/likedbg/stages/debugger.py` (pass `port` to `build_gdb_args`)
- Test: `tests/test_stage_debuggee.py`, `tests/test_stage_debugger.py`

**Interfaces:**
- Consumes: launcher params (Task 7), `build_gdb_args(port=...)` (Task 6), `host.network_mode`/`host.accel`, `settings.debuggee.gdb_port`.

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_stage_debuggee.py` (build a Linux host-net/kvm context):
```python
def _linux_ctx(*, accel="tcg"):
    host = HostProfile(
        os="linux", host_arch="arm64", accel=accel, debuggee_mode="in-container",
        storage_mode="bind", gdbstub_addr="localhost", ssh_addr="localhost", network_mode="host",
    )
    ctx = PipelineContext(settings=Settings.model_validate({"general": {"arch": "arm64"}}), host=host)
    ctx.kernel_image = Path("/ws/artifacts/ksrc/x/arch/arm64/boot/Image")
    ctx.rootfs_image = Path("/ws/artifacts/rootfs/r.img")
    return ctx


def test_linux_in_container_uses_host_network():
    sent = {}
    DebuggeeStage(send=lambda cmd: sent.setdefault("cmd", cmd), debuggee_image="like_debuggee:latest").run(_linux_ctx())
    assert "--network host" in sent["cmd"]
    assert "-p 1234:1234" not in sent["cmd"]
    assert "/dev/kvm" not in sent["cmd"]  # tcg → no kvm device


def test_linux_kvm_passes_device():
    sent = {}
    DebuggeeStage(send=lambda cmd: sent.setdefault("cmd", cmd), debuggee_image="like_debuggee:latest").run(
        _linux_ctx(accel="kvm")
    )
    assert "--device /dev/kvm" in sent["cmd"]
```
Append to `tests/test_stage_debugger.py` a test that a custom port reaches gdb. First read the existing `tests/test_stage_debugger.py` to reuse its context helper; then add:
```python
def test_debugger_threads_custom_gdb_port():
    captured = {}
    settings = Settings.model_validate({"general": {"arch": "arm64"}, "debuggee": {"gdb_port": 4444}})
    host = HostProfile(
        os="linux", host_arch="arm64", accel="tcg", debuggee_mode="in-container",
        storage_mode="bind", gdbstub_addr="localhost", ssh_addr="localhost", network_mode="host",
    )
    ctx = PipelineContext(settings=settings, host=host)
    ctx.vmlinux = Path("/ksrc/x/vmlinux")
    DebuggerStage(ext="gef", run_gdb=lambda args: captured.setdefault("args", args), breakpoint=None).run(ctx)
    assert "gef-remote localhost 4444" in " ".join(captured["args"])
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_stage_debuggee.py tests/test_stage_debugger.py -q`
Expected: FAIL (debuggee still emits `-p 1234:1234`; debugger ignores `gdb_port`).

- [ ] **Step 3: Implement**

In `src/likedbg/stages/debuggee.py`, in the `in-container` branch of `run()`:
```python
        if ctx.host.debuggee_mode == "in-container":
            rw_mounts = [ctx.rootfs_image] if ctx.rootfs_image is not None else []
            cmd = qemu_container_command(
                argv, image=self._debuggee_image, ro_mounts=[ctx.kernel_image], rw_mounts=rw_mounts,
                gdbstub_port=ctx.settings.debuggee.gdb_port,
                network_mode=ctx.host.network_mode, kvm=ctx.host.accel == "kvm",
            )
```
In `src/likedbg/stages/debugger.py`, in `run()`, pass the port:
```python
        args = build_gdb_args(
            ctx.host, arch=ctx.settings.general.arch, vmlinux=ctx.vmlinux, ext=self._ext,
            breakpoint=self._breakpoint, port=ctx.settings.debuggee.gdb_port,
        )
```

- [ ] **Step 4: Run to verify they pass (macOS published in-container test stays green)**

Run: `uv run pytest tests/test_stage_debuggee.py tests/test_stage_debugger.py -q`
Expected: PASS (existing `test_in_container_debuggee_wraps_docker_run` keeps `-p 1234:1234`: its macOS host has the default `network_mode="published"`).

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/stages/debuggee.py src/likedbg/stages/debugger.py tests/test_stage_debuggee.py tests/test_stage_debugger.py
git commit -m "feat(stages): thread gdb_port/network_mode/kvm into Debuggee & Debugger"
```

---

### Task 10: CLI — thread host, drop the gate, bind `--use`, adopt guard

**Files:**
- Modify: `src/likedbg/cli.py` (`build_pipeline`/`build_use_pipeline` gain `host`; `run_gdb` threads `storage_mode`+`network_mode`; compute `chown_to`; `cmd_use` bind image; delete `require_volume_mode` + call sites; adopt guard)
- Test: `tests/test_cli.py` (update pipeline-builder calls; delete `require_volume_mode` tests; add adopt-guard test)

**Interfaces:**
- Consumes: everything above. `build_pipeline(..., host: HostProfile)`, `build_use_pipeline(..., host: HostProfile)`.
- Produces: a CLI that runs bind end-to-end; `_require_volume_for_adopt(host)` (raises on non-volume).

- [ ] **Step 1: Update the existing tests + add the adopt-guard test**

In `tests/test_cli.py`:
- Remove the import `from likedbg.cli import require_volume_mode` and **delete** `test_require_volume_mode_accepts_volume` and `test_require_volume_mode_rejects_bind`.
- Add `from likedbg.cli import _require_volume_for_adopt`.
- In `test_build_pipeline_includes_all_stage_names`, add `host=_host("volume")` to the `build_pipeline(...)` kwargs.
- In `test_build_use_pipeline_is_launch_only`, add `host=_host("volume")` to the `build_use_pipeline(...)` kwargs.
- Append:
```python
def test_adopt_guard_rejects_bind():
    with pytest.raises(HostCapabilityError):
        _require_volume_for_adopt(_host("bind"))


def test_adopt_guard_accepts_volume():
    _require_volume_for_adopt(_host("volume"))  # no raise
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/test_cli.py -q`
Expected: FAIL (`_require_volume_for_adopt` undefined; `build_pipeline`/`build_use_pipeline` reject `host`).

- [ ] **Step 3: Implement**

In `src/likedbg/cli.py`:

Replace `require_volume_mode` with the narrow adopt-only guard:
```python
def _require_volume_for_adopt(host: HostProfile) -> None:
    if host.storage_mode != "volume":
        raise HostCapabilityError(
            "--adopt migrates the legacy in-volume tree and is volume-mode only",
            remedy="bind/Linux builds fresh — just run start_kgdb",
        )
```
Add `host: HostProfile` to `build_pipeline`'s signature and thread it into `run_gdb`:
```python
def build_pipeline(container, session, *, host, workspace, kernel_volume, dl_dir, debugger_image,
                   debuggee_image, ext, panes, build_recipe, rootfs_recipe) -> Pipeline:
    ...
    def run_gdb(args):
        loc = cache.locations(
            build_recipe.label, arch=build_recipe.arch, storage_mode=host.storage_mode,
            workspace=workspace, volume=kernel_volume,
        )
        session.select_pane(debugger_pane)
        session.send_keys(gdb_pane_command(
            args, image=debugger_image, mount_source=loc.gdb_mount_source, network_mode=host.network_mode,
        ))
```
Add `host` to `build_use_pipeline` and thread `network_mode` into its `run_gdb`:
```python
def build_use_pipeline(container, session, *, host, workspace, kernel_volume, debugger_image,
                       debuggee_image, ext, panes, gdb_mount_source) -> Pipeline:
    ...
    def run_gdb(args):
        session.select_pane(debugger_pane)
        session.send_keys(gdb_pane_command(
            args, image=debugger_image, mount_source=gdb_mount_source, network_mode=host.network_mode,
        ))
```
In `cmd_use`, after `require_volume_mode(host)` is removed, pick the host image path for bind:
```python
    kernel_image_path = bm.paths["image_host"] if bm.storage_mode != "volume" else bm.paths["image_in_tree"]
    ...
    ctx = PipelineContext(
        settings=use_settings, host=host,
        kernel_root=Path(bm.paths["kernel_root"]),
        vmlinux=Path(bm.paths["gdb_vmlinux"]),
        kernel_image=Path(kernel_image_path),
        rootfs_image=rootfs_image,
        build_label=label, rootfs_label=rlabel,
    )
    pipeline = build_use_pipeline(container, session, host=host, workspace=workspace, ...)
```
(Delete the `require_volume_mode(host)` line in `cmd_use`.)

In `main`, the default-run path: delete `require_volume_mode(host)`; compute `chown_to`; pass `host` + `chown_to` into the pipeline:
```python
        host = HostProfile.detect(settings, workspace)
        _ensure_images(container, workspace, specs=images.required_for(host))
        chown_to = (os.getuid(), os.getgid()) if host.os == "linux" and host.storage_mode == "bind" else None
        ...
        pipeline = build_pipeline(container, session, host=host, workspace=workspace, ...,
                                  build_recipe=br, rootfs_recipe=rr)
```
`BuildStage` is constructed inside `build_pipeline`; pass `chown_to` through. Add `chown_to` to `build_pipeline`'s signature (`*, host, chown_to=None, ...`) and to the `BuildStage(...)` call there:
```python
            BuildStage(container, recipe=build_recipe, kbuilder_image=KBUILDER_IMAGE,
                       workspace=workspace, kernel_volume=kernel_volume, chown_to=chown_to),
```
Guard `--adopt` (in `main`, the adopt branch) — detect the host first, then guard:
```python
        if args.adopt:
            _require_volume_for_adopt(HostProfile.detect(settings, workspace))
            label = adopt_legacy_build(container, workspace=workspace, recipe=br)
            ...
```

- [ ] **Step 4: Run the full suite green**

Run: `uv run pytest -q`
Expected: PASS (whole suite). Then the gate: `uv run ruff check src tests && uv run ruff format --check src tests && uv run mypy src/likedbg`.

- [ ] **Step 5: Commit**

```bash
git add src/likedbg/cli.py tests/test_cli.py
git commit -m "feat(cli): thread host/storage_mode/network_mode + chown; bind --use; adopt guard; drop require_volume_mode"
```

---

## Live-gate verification (controller-run, NOT a subagent task)

After all tasks merge into `feat/b3-bind-linux`, the controller runs the live gate on the arm64 Ubuntu 26.04 VM (`ssh pwn@192.168.233.128`, key already planted) per spec §6. This is **not** a TDD task — it needs the VM and real Docker, and uses the `verify` skill.

1. Prep: `ssh` in, install `uv` (only hard gap), `rsync` the repo over (exclude `.venv`, `.git`, `artifacts`), `uv run ./start_kgdb --build-images`.
2. **x86_64 config:** `uv run ./start_kgdb` → cross-compiled kernel → foreign-arch amd64 rootfs (host binfmt) → in-container **TCG** boot → containerized gdb `hbreak start_kernel` → `continue` → systemd userspace.
3. **arm64 config:** same, in-container TCG (no `/dev/kvm` on this VM).
4. **Bind asserts:** tree at `artifacts/ksrc/<label>/` owned by `pwn` (editable, no sudo); `--list`/`--clean <label>` work; no leftover containers.
5. **Topology branches:** also run once with `network = published` and a non-default `gdb_port` to exercise those branches live.
6. **macOS no-regression:** an arm64 volume-mode run on the M5 still works via native-HVF.

KVM passthrough (`--device /dev/kvm`) is **not** live-gated here (no `/dev/kvm` on the VM) — unit-tested only, per spec §7.

## Self-review

- **Spec coverage:** §3.1 config→T1; §3.2 host_profile→T2; §3.3 locations+helper→T3; §3.4 build/unpack+chown→T8; §3.5 export (no change, asserted via T8 bind kernel_image)→covered; §3.6 launchers→T7; §3.7 stage wiring→T9; §3.8 qemu→T5; §3.9 cli→T10; §3.10 remove_cached→T4; §3.11 adopt guard→T10; gdbcmd port→T6. All §3 components have a task.
- **Placeholder scan:** none — every code/test step shows full code.
- **Type consistency:** `tree_mount_source(workspace, *, storage_mode, volume)` (defined T3, consumed T8); `HostProfile.network_mode` (T2, consumed T7/T9/T10); `BuildStage(chown_to=...)` (T8, consumed T10); `qemu_container_command(..., network_mode, kvm, gdbstub_port)` (T7, consumed T9); `build_gdb_args(..., port)` (T6, consumed T9); `_require_volume_for_adopt` (T10). Consistent across tasks.

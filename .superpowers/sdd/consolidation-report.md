# Consolidation Report

## Before / After

**Before**: 40 FAILED (across test_qemu, test_stage_build, test_stage_debuggee, test_stage_debugger, test_stage_download, test_stage_export, test_stage_rootfs, test_stage_unpack).

**After**: 45 FAILED / 215 passed. All failures are in the DO-NOT-TOUCH set (test_qemu, test_gdbcmd, test_stage_download, test_stage_debuggee, test_stage_debugger, test_cli, test_pipeline). None of the files I touched are failing.

*(The before count of 40 did not include test_cli, test_pipeline, test_gdbcmd which were also already failing but truncated in the initial output; the total DO-NOT-TOUCH failures = 45.)*

## Actions Taken

### 1. Merged relocated host_profile tests (Action 1 of brief)
- Added `test_native_resolves_to_host_arch` and `test_explicit_cross_arch_kept` to `tests/test_host_profile.py` using a `_simple_probes` helper (to avoid conflicting with the existing `_probes` signature).
- `git rm src/tests/test_host_profile.py`

### 2. Ported patch-ordering test; deleted legacy builder file (Action 2 of brief)
- Added `test_patches_applied_in_order` to `tests/test_stage_build.py`, reusing the existing `_BuildFakeC` and `_ctx` helpers. `_build_recipe` imported with an alias to avoid collision with the existing `_recipe` helper.
- `git rm -r src/tests/` (removed `__init__.py`, `test_kernel_builder.py`, `test_host_profile.py`, `confs/`, `files/`).

### 3. Migrated canonical tests to new APIs

**`tests/test_cache_recipes.py`** — Rewrote:
- `kernel_builder` → `build` in all `Settings.model_validate` calls.
- Added `arch="arm64"` explicit kwarg to all `build_recipe(...)` calls.
- `general.kernel_tag` → `build.label_suffix`.
- `rootfs_recipe(settings)` → `rootfs_recipe(settings, arch="arm64")` to pass explicit arch.

**`tests/test_stage_build.py`** — Fixed `_ctx`:
- `kernel_builder` → `build` in Settings construction.
- Added `target_arch="arm64"` to `HostProfile(...)` literal.

**`tests/test_stage_rootfs.py`** — Added `target_arch="arm64"` to `HostProfile(...)` in `_ctx`.

**`tests/test_stage_unpack.py`** — Added `target_arch="arm64"` to both `HostProfile(...)` literals (`_ctx` + `test_archive_outside_workspace_raises_unpack_error`).

**`tests/test_stage_export.py`** — Added `target_arch="arm64"` to `HostProfile(...)` in `_ctx`.

**`tests/test_images.py`** — Added `target_arch="arm64"` to `HostProfile(...)` in `_host`.

### 4. Deleted legacy config test and INI fixtures (Action 3 of brief, last bullet)
- `git rm tests/test_config.py` — tests the legacy INI `load_settings` path (Task 18 removal).
- `git rm tests/fixtures/system.ini tests/fixtures/user.ini` — confirmed no DO-NOT-TOUCH file references these (grepped; only `test_config.py` used them).

## Remaining FAILED files (all DO-NOT-TOUCH)
- `tests/test_qemu.py` (11 failures) — uses `debuggee.memory` (old field), missing `target_arch`
- `tests/test_gdbcmd.py` (11 failures) — `HostProfile` missing `target_arch`, old Settings fields
- `tests/test_stage_download.py` (3 failures) — future task
- `tests/test_stage_debuggee.py` (4 failures) — future task
- `tests/test_stage_debugger.py` (2 failures) — future task
- `tests/test_cli.py` (7 failures) — uses old `build_recipe` sig, `HostProfile` missing `target_arch`
- `tests/test_pipeline.py` (4 failures) — `HostProfile` missing `target_arch`

**Total: 45 failed (all DO-NOT-TOUCH), 215 passed**

## Interpretations / Concerns

1. **`test_patches_applied_in_order` in src/tests used `_host_profile(tmp_path)`** (via `HostProfile.detect`) while the tests/test_stage_build.py helpers use a manually-constructed `HostProfile`. I adapted it to use the existing `_ctx` helper (which now has `target_arch="arm64"`) and pass `ctx.build_label = r.label` before the stage run. The test still asserts `len(patch_cmds) == 2`, which is the core behavioral check.

2. **`rootfs_recipe(settings)` old call** — The brief says `rootfs_recipe` arch param is optional `arch: Arch | None`. Tests that passed `None` or no arch still work fine since `arch or settings.general.arch` is the fallback. In test_cache_recipes I added `arch="arm64"` explicitly for clarity and correctness; in test_stage_build context the `rootfs_recipe` isn't called so no change needed there.

3. **DO-NOT-TOUCH files `test_cli.py`/`test_pipeline.py`**: These were already failing before my edits (with the same `HostProfile`/Settings API breakage). My changes did not cause new failures in those files.

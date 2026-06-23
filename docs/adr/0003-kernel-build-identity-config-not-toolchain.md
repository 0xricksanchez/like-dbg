# Kernel Builds are identified by requested config, not toolchain identity

The Build Cache keys a Kernel Build by an automatic content-hash of its **requested
configuration** — kernel version, arch, compiler choice (clang/gcc), and kconfig fragment
contents. We deliberately **exclude** the kbuilder/rootfs Docker image identity and the
resolved compiler *version* (which lives unpinned inside `like_kbuilder_arm64:latest`) from
the key.

A cached Kernel Build is a finished artifact: it boots and debugs identically regardless of
later toolchain changes, so the image that produced it is orthogonal to *what was requested*.
Folding the image ID into the key would force surprise rebuilds of working kernels whenever
an unrelated image is rebuilt (over-invalidation), and bit-for-bit toolchain reproducibility
is an explicit non-goal.

## Consequences

- A deliberate toolchain bump does **not** auto-rebuild existing configs. To recompile a
  config with a changed toolchain, use `--force-rebuild` (or `--clean <label>` then re-run).
- When patches / `custom_modules` / a rootfs package list are eventually wired into the
  stages, those inputs **must** be added to the respective `cache_inputs` in the same change
  — they affect output and belong in the key, unlike toolchain image identity.

## Considered and rejected

Including the kbuilder image **ID/digest** (or a `clang --version` probe) in the key. It
closes a "silent stale toolchain" gap, but that gap isn't a correctness bug (the build still
boots) — only a freshness preference we don't hold — and the cost is rebuilding every cached
kernel after any image rebuild. The explicit `--force-rebuild` escape hatch covers the rare
intentional case without penalizing the common path.

# Container-image currency: content-hash of declared build inputs; warn, don't auto-rebuild

The package keeps each Container image current via a **content hash of an explicitly-declared
set of build inputs** — the image's dockerfile plus any local files it bakes in (`COPY`/`ADD`) —
stamped onto the built image as the Docker label `likedbg.input_sha`. On a run, a **missing**
required image is auto-built; a **present** image whose live label no longer matches the
recomputed hash is reported **stale** with a loud warning (the run still proceeds), and
`start_kgdb --build-images` is the refresh that rebuilds and re-stamps. The declared
`build_inputs` list is kept honest by a test that parses each dockerfile's `COPY`/`ADD`
directives and fails if any local source is absent from that image's `build_inputs`.

This mirrors ADR-0003: identity is a content hash over the inputs we **declare**, not over
everything that could conceivably matter. We deliberately **exclude** upstream drift (the
`ubuntu` base tag, the gef/pwndbg clones fetched at build time) from the hash — only local
build-input *content* is tracked. A stale image is a freshness signal, not a correctness
failure we should silently fix mid-run; the explicit refresh keeps the common path fast.

## Consequences

- Editing a dockerfile **or a baked script** (e.g. `io/scripts/rootfs.sh`) changes the image's
  `input_sha`, so the next run warns it is stale until `--build-images` rebuilds + re-stamps it.
  This closes the gap that caused the earlier rootfs bug (a changed baked script with no rebuild).
- Adding a new `COPY`/`ADD` of a local file to a dockerfile **requires** adding that file to the
  image's `build_inputs` in the same change — the completeness test fails otherwise (the same
  rule ADR-0003 states for output-affecting cache inputs).
- Staleness **warns, never auto-rebuilds**: no surprise multi-minute rebuild interrupts a run.
- Upstream drift is **not** detected: a rebuilt `ubuntu:26.04` base or a newer upstream
  gef/pwndbg does not move the hash. `--build-images` is the deliberate way to pick those up.

## Considered and rejected

- **Runtime `COPY`/`ADD` parsing** to derive build inputs automatically. Rejected for the live
  path: globs, directory copies, and `.dockerignore` make correct expansion fragile. We keep the
  parsing at **test** time only (a completeness guard), where a conservative, strict check that
  fails on unhandled patterns is acceptable.
- **mtime comparison** (image creation time vs input file mtimes). Rejected: git checkouts and
  tooling rewrite mtimes unpredictably, producing false stale/fresh verdicts. Content hashing is
  deterministic.
- **Auto-rebuild on stale** (rebuild the image mid-run instead of warning). Rejected: it injects
  surprise multi-minute builds into a run; the explicit `--build-images` escape hatch is better.
- **No staleness detection** (only build-if-missing). Rejected: build-if-missing never fires for
  a present-but-stale image, so the rootfs-bug class would recur.

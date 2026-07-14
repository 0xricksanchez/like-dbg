# Contributing to LIKE-DBG

Thanks for taking an interest in LIKE-DBG. Contributions that make kernel debugging,
exploit development, and CTF workflows clearer, more reliable, or easier to use are welcome.

For questions, early ideas, and design discussions, use
[GitHub Discussions](https://github.com/0xricksanchez/like-dbg/discussions). For a reproducible
problem or a scoped proposal, open an
[issue](https://github.com/0xricksanchez/like-dbg/issues). Please read the
[Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Before you start

LIKE-DBG is a Python 3.12+ project that runs its build and test tooling through
[uv](https://docs.astral.sh/uv/). The lab itself also needs Docker and tmux. See the
[README](README.md#requirements) for the full host requirements and setup instructions.

Fork the repository, create a branch from `main`, then install the development environment:

```sh
uv sync
```

The main Python package is in `src/likedbg/`; tests live in `tests/`. Configuration defaults,
profiles, scenarios, and kernel config fragments live in `configs/`. The project documentation
in `docs/` describes the supported workflows and should stay in step with user-facing changes.

## Making a change

Keep each pull request focused. Explain the problem it solves, describe the approach, and call
out any changes to configuration, host requirements, Docker images, or guest behaviour.

Add or update tests for behaviour changes. Update the relevant documentation when a command,
configuration option, profile, workflow, or supported platform changes. Changes to Dockerfiles or
baked scripts require rebuilding the images before a live test:

```sh
just build-images
```

Do not include generated run artifacts, local configuration, caches, or unrelated formatting
changes in a pull request.

## Checks

Run these checks before opening a pull request:

```sh
just test
just lint
```

`just test` runs the pytest suite. `just lint` runs Ruff's lint and format checks, followed by
strict mypy checks for `src/likedbg`. The continuous integration workflow runs the same quality
checks and collects test coverage.

For a small, isolated change, start by running the affected test file while you work, then run
the full checks before submitting:

```sh
uv run pytest tests/test_config_loader.py -q
```

## Reporting bugs

Please include enough detail for someone else to reproduce the issue:

- A short description of the problem and the expected result.
- The command and relevant configuration or scenario.
- Host operating system, architecture, Docker runtime, and Python version.
- The relevant logs, error output, or a minimal reproducer.
- Whether the issue occurs with a self-built kernel, a foreign kernel, or both.

Remove credentials, private images, challenge files, and other sensitive material before posting.

## Pull requests

Pull requests are reviewed through the usual GitHub flow:

1. Fork the repository and branch from `main`.
2. Make a focused change with tests and documentation where needed.
3. Run `just test` and `just lint`.
4. Open a pull request that explains what changed and how you verified it.

Maintainers may ask for changes, suggest a different direction, or close a proposal that does not
fit the project's goals. That is part of keeping the project maintainable.

## License

By contributing, you agree that your contributions are licensed under the repository's
[MIT License](LICENSE).

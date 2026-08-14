# Contributing to degc

Thanks for your interest! degc (Docker Egress Gateway Controller) is a small,
focused controller that policy-routes selected containers' egress through a VPN
gateway, fail-closed. Bug reports, docs, and code are all welcome.

## Getting started

Pure-Rust build, no system libraries needed:

```sh
cargo build
cargo test
```

Enforcing against the real kernel needs root (`CAP_NET_ADMIN`) plus `nft` and
`ip` on the host. Without it, use `--dry-run`, which resolves the plan and logs
the exact nftables + routing it would program, touching nothing.

## Before you open a PR

Run the same checks CI does:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --locked
cargo test --locked
cargo deny check
```

Enforcement changes should be exercised end-to-end: `test/run.sh` spins up a
throwaway Docker network + a labelled member and verifies marking, routing,
fail-closed behaviour and clean teardown (needs Docker; scoped + reversible).

## Conventions

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `refactor:`, `docs:`, `ci:`), with the *why* in the body.
- Keep changes focused; match the surrounding style (`rustfmt`, no `unsafe`).
- Prefer updating existing files over adding new ones; update docs and tests
  alongside behaviour changes.

## Design

See [`docs/architecture.md`](docs/architecture.md) for how degc works and its
kill-switch correctness argument.

## License

By contributing, you agree that your contributions are licensed under the
**MIT License**, the same as the project.

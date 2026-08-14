---
name: Bug report
about: Something isn't working
labels: bug
---

<!-- For security issues, DO NOT open an issue — use the Security tab. -->

## What happened

A clear description of the bug, and what you expected instead.

## Reproduction

- degc version / commit:
- How degc is run (compose snippet or `docker run`, `--dry-run`?):
- Your gateways config and the `<prefix>.enable` / `<prefix>.via` labels:
- The resolved plan if you have it (`degc status`, or the `--dry-run` log):

## Environment

- OS / kernel:
- Docker version:
- Gateway type (host `wg` interface, gluetun container, …):
- IPv4, IPv6, or dual-stack:

## Logs

```
(degc log output, RUST_LOG=debug if possible)
```

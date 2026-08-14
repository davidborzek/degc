# Security Policy

degc is a **privileged network daemon**: it runs with `CAP_NET_ADMIN` in the
host network namespace, reads the Docker API, and programs the host's nftables
(`inet degc`) plus policy-routing rules. It is privacy-critical — its job is a
fail-closed kill-switch that keeps a member container's traffic on the VPN and
never leaks it to the WAN. Bugs here matter, so reports are taken seriously.

## Supported versions

degc is pre-1.0. Only the latest release (and `main`) receive security fixes.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Use GitHub's private vulnerability reporting:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue, affected version/commit, and a reproduction if possible.

You can expect an acknowledgement within a few days. Once a fix is available it
will be released and the advisory published with credit (unless you prefer to
remain anonymous).

## Scope

Especially relevant:

- **Leaks:** a member's marked traffic reaching the WAN directly instead of the
  gateway (kill-switch bypass), or IPv6 egress escaping unfiltered.
- Ways to make degc program rules outside its own `inet degc` table / routing
  table, or flush a routing table it does not own.
- Table / fwmark collisions with other tools that misroute traffic.
- Privilege or Docker-socket handling issues.

Out of scope: the tunnel provider's own kill-switch (the gateway container's
responsibility), operator misconfiguration, and the inherent trust in the
Docker API degc is pointed at.

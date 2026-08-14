# degc — Docker Egress Gateway Controller

**Route selected containers' internet egress through a shared VPN gateway — with
a label, fail-closed, no per-app sidecar.**

[![CI](https://github.com/davidborzek/degc/actions/workflows/ci.yaml/badge.svg)](https://github.com/davidborzek/degc/actions/workflows/ci.yaml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/davidborzek/degc?sort=semver)](https://github.com/davidborzek/degc/releases)

degc is a small controller for a single Docker host. A container opts in with a
label; degc marks that container's internet-bound packets and policy-routes them
through a VPN gateway (e.g. a [gluetun](https://github.com/qdm12/gluetun)
container), while its LAN / inter-container traffic keeps its normal path. If the
gateway is down the traffic is dropped, never leaked (a fail-closed kill-switch).

```yaml
services:
  qbittorrent:
    image: ghcr.io/home-operations/qbittorrent
    labels:
      degc.enable: "true"     # send this container's internet egress via a gateway
      degc.via: "vpn"         # which gateway
```

The app stays on the flat Docker network with its own identity — no
`network_mode: service:…` juggling, no gluetun sidecar per app. One shared
gateway, and a label per container that should ride it.

degc only *routes* egress; it never runs the VPN itself. Bring your own tunnel —
a gateway container (gluetun/WireGuard), a host WireGuard interface, or a static
next-hop router — and degc policy-routes the opted-in containers through it,
fail-closed. It is a host-level daemon, not a per-app sidecar.

## How it works

Every reconcile (on Docker events + a resync interval) degc rebuilds, from the
current container snapshot, an nftables table `inet degc` + a policy-routing
table per gateway:

1. **mark** a member's internet-bound packets (`ip saddr @members`, excluding
   `localSubnets`) — LAN and inter-container traffic stay direct;
2. **policy-route** marked packets (`ip rule fwmark … lookup <table>`) to the
   gateway, with a **blackhole** installed *before* the rule so traffic can never
   fall through to the WAN while routes are (re)installed;
3. **kill-switch**: marked traffic may leave only via the egress — anything else
   is dropped; IPv6 egress of members is dropped (not routed).

State is derived fresh from Docker every reconcile — container IPs are never
hardcoded, so a gateway/app recreate just updates the routes. See
[docs/architecture.md](docs/architecture.md) for the data plane and the
kill-switch correctness argument.

## Quickstart

A shared gluetun gateway + one member. The gateway **declares itself** with a
label, so no separate config file is needed:

```yaml
services:
  degc:
    image: ghcr.io/davidborzek/degc
    container_name: degc
    network_mode: host          # rules + policy routing live in the host netns
    cap_add: [NET_ADMIN]
    cap_drop: [ALL]
    read_only: true
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  vpn:                          # the shared VPN gateway (gluetun)
    image: qmcgaw/gluetun
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    environment:
      VPN_SERVICE_PROVIDER: <your-provider>
      VPN_TYPE: wireguard
      FIREWALL_OUTBOUND_SUBNETS: "172.18.0.0/16"   # your Docker network subnet
    volumes:
      # makes gluetun forward + masquerade other containers onto the tunnel
      - ./post-rules.txt:/iptables/post-rules.txt:ro
    labels:
      degc.gateway: "vpn"       # "I am the gateway named 'vpn'"

  qbittorrent:
    image: ghcr.io/home-operations/qbittorrent
    labels:
      degc.enable: "true"
      degc.via: "vpn"
```

`post-rules.txt` (gluetun gateway mode — forward + masquerade your Docker subnet
onto the tunnel; `tun0` is gluetun's WireGuard interface):

```
iptables -A FORWARD -s 172.18.0.0/16 -o tun0 -j ACCEPT
iptables -A FORWARD -d 172.18.0.0/16 -i tun0 -j ACCEPT
iptables -t nat -A POSTROUTING -s 172.18.0.0/16 -o tun0 -j MASQUERADE
```

A full example lives in [`examples/`](examples/). Requires `CAP_NET_ADMIN`, the
host network namespace, and `nft` + `ip` in the image (both included).

## Configuration

**Containers** opt in with labels (they follow the [label-spec](LABEL-SPEC.md);
`degc` is the default prefix, set `DEGC_LABEL_PREFIX` to change it):

| label | meaning |
| --- | --- |
| `degc.enable: "true"` | route this container's internet egress via a gateway |
| `degc.via: "<name>"` | which gateway (optional if there's a single / default one) |
| `degc.gateway: "<name>"` | *on a gateway container:* declare it as gateway `<name>` |
| `degc.gateway.mark: "0x…"` | *on a gateway container:* fwmark override (default: auto-derived from the name) |
| `degc.gateway.table: "<n>"` | *on a gateway container:* routing-table id override (default: auto-derived) |
| `degc.gateway.snat: "true"` / `"false"` | *on a gateway container:* masquerade onto the egress (default: inferred — `true` for an interface, `false` for a container) |
| `degc.gateway.localSubnets: "<cidr>,…"` | *on a gateway container:* direct, never-tunnelled nets (default: the RFC1918 ranges) |
| `degc.gateway.default: "true"` | *on a gateway container:* make this the gateway for `degc.enable` without `degc.via` |
| `degc.gateway.members: "<k>=<v>,…"` | *on a gateway container:* selector — route matching containers **without** a `degc.enable` label |

> ⚠️ A container whose `degc.via` names no known gateway is **not routed** — its
> egress goes out normally (not fail-closed). This is surfaced as a warning in
> the logs and in `degc status`, so check status after adding members.

### Selecting which containers route

Two ways, and explicit opt-in always wins:

- **Per-container opt-in** (default, safest): the container carries
  `degc.enable` / `degc.via`. Local and auditable — each app declares its own
  intent, so nothing is routed (or missed) by accident.
- **Selector** (central): a gateway lists `members` selectors; any
  container matching one is routed **without** a `degc.enable` label. A
  container matching two gateways' selectors is a **conflict** — surfaced and
  **not routed** (degc never guesses an egress); set an explicit `degc.via` to
  disambiguate. A selector matches a container when all its listed labels match.

**Gateways** are either self-declared by a gateway container's labels
(`degc.gateway` + optional `degc.gateway.<field>` knobs — no `gateways.yaml`
needed) or listed in a `gateways.yaml` (`DEGC_GATEWAYS_PATH`). The config is
deliberately number-free — a gateway is just a name and an egress:

```yaml
- name: vpn
  egress:
    container: vpn        # a gateway container (resolved to its live IP), OR
    # interface: wg0      # a host WireGuard interface, OR
    # nextHop: 10.0.0.1   # a static next-hop router
  # everything below is OPTIONAL:
  # snat:  inferred (true for a host interface, false for a container gateway)
  # mark:  auto-derived from the name (stable); set only to resolve a collision
  # table: auto-derived from the name; set only to resolve a collision
  # localSubnets: defaults to the RFC1918 ranges (kept direct, never tunnelled)
  members:                # OPTIONAL central selection (else use degc.enable):
    - com.docker.compose.service: sabnzbd   # route this service, no per-app label
    - vpn: "true"                           # or anything tagged vpn=true
```

The fully label-driven equivalent needs no `gateways.yaml` at all — put it on
the gateway container:

```yaml
    labels:
      degc.gateway: "vpn"
      degc.gateway.members: "vpn=true"   # route every container tagged vpn=true
```

`degc validate [file]` checks a config; `degc status` shows the resolved plan;
`degc schema` emits the JSON Schema; `degc down` removes degc's host state (the
daemon leaves it in place on stop, so a crash stays fail-closed).

## DNS

degc routes IP egress, not name resolution. If a member resolves via Docker's
embedded DNS (`127.0.0.11`), those queries exit via the host's resolver, **not**
the tunnel — a DNS leak even though the data connections go through the VPN. To
avoid it, point the member's resolver at the gateway or a public resolver so DNS
rides the tunnel too, e.g.:

```yaml
    dns: ["<your-vpn-dns>"]     # the VPN provider's in-tunnel resolver
```

## Observability

Set `DEGC_METRICS_ADDR` (e.g. `0.0.0.0:9101`) to expose Prometheus metrics at
`/metrics` plus `/healthz` and `/readyz`. Notable series: `degc_ready`,
`degc_reconciles_total{trigger,result}`, `degc_members`, and
`degc_gateway_available{gateway}` (1 = egress resolved, 0 = fail-closed).

Logs (stderr, `RUST_LOG`-controlled, default `info`): each reconcile that
**changes** the applied state logs a one-line summary at INFO — per gateway its
egress and members, e.g. `vpn=via 172.18.0.24 members=2[sonarr,sabnzbd]` — plus
a warning for any unresolved/conflicting/malformed entry. A reconcile that
changes nothing (the periodic resync) stays at DEBUG, so INFO reflects real
activity. Set `RUST_LOG=degc=debug` to see every reconcile tick.

## Security

degc is a privileged, privacy-critical daemon. See [SECURITY.md](SECURITY.md)
for the threat model and how to report issues. In short: it runs with
`CAP_NET_ADMIN` in the host netns and owns only its `inet degc` table + routing
table; the VPN-down kill-switch itself is the gateway container's job (run
gluetun with its firewall on), while degc guarantees fail-closed for a
gateway-down / not-yet-routed state.

## Status

Pre-1.0. The core + enforcement work and are covered by unit tests, a
real-kernel (throwaway-netns) check, and an end-to-end harness
([`test/run.sh`](test/run.sh)). Interfaces may still change before 1.0.

## License

[MIT](LICENSE).

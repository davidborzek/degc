# Example: shared gluetun VPN gateway

`qbittorrent` rides the `vpn` gateway (a [gluetun](https://github.com/qdm12/gluetun)
container) purely via labels — no `network_mode: service:vpn`, no per-app
sidecar. Add more members by putting the same two `degc.enable` / `degc.via`
labels on them.

1. Set your VPN provider + credentials on the `vpn` service.
2. Make sure the Docker subnet matches in three places: the network `subnet`,
   gluetun's `FIREWALL_OUTBOUND_SUBNETS`, and `post-rules.txt`.
3. `docker compose up -d`, then check `docker run --rm --network host \
   --cap-add NET_ADMIN --entrypoint degc ghcr.io/davidborzek/degc status`.

The `post-rules.txt` is what makes gluetun forward other containers' traffic
onto the tunnel (stock gluetun only routes its own netns). degc handles the
host-side marking + policy routing + kill-switch; gluetun handles the tunnel +
the VPN-down kill-switch.

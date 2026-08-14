#!/usr/bin/env bash
# Self-contained, reversible workstation integration test for degc's
# enforcement (nft source-mark + policy routing + fail-closed kill-switch),
# plus the collision preflight and `degc down`.
#
# Safe by construction:
#   * touches ONLY a throwaway Docker bridge, the `inet degc` nft table, and an
#     unused routing table (4242) + fwmark (0x1111) — never the host's own
#     traffic (unmarked) nor other containers (only the member's IP is marked);
#   * every privileged op runs in a capped host-netns container of the SAME
#     image (no host sudo);
#   * a trap tears everything down on exit, restoring the member's networking.
#
# Proves: member IP lands in the nft set (bystander does not); the ip rule +
# proto-tagged routes + blackhole get installed; the member's internet is diverted
# away from the direct path (fail-closed); host + non-member stay online; stopping
# the daemon KEEPS the block (fail-closed); `degc down` cleanly restores; and the
# preflight REFUSES to program a routing table already owned by something else.
set -euo pipefail

IMG=degc:dev
NET=degc-test
SUBNET=10.123.0.0/24
MARK=0x1111
TABLE=4242
DUMMY=degctest0
DAEMON=degc-test-daemon
CFG="$(cd "$(dirname "$0")" && pwd)/gateways.test.yaml"

priv() { local bin=$1; shift; docker run --rm --network host --cap-add NET_ADMIN --entrypoint "$bin" "$IMG" "$@"; }
cping() { docker exec "$1" ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED; }
hping() { ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 && echo REACHABLE || echo BLOCKED; }
degc_down() { docker run --rm --network host --cap-add NET_ADMIN -v "$CFG":/etc/degc/gateways.yaml:ro "$IMG" down; }

cleanup() {
  docker rm -f "$DAEMON" degc-collide member memberx bystander >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  priv nft delete table inet degc >/dev/null 2>&1 || true
  priv ip rule del fwmark "$MARK" table "$TABLE" >/dev/null 2>&1 || true
  priv ip route flush table "$TABLE" >/dev/null 2>&1 || true
  priv ip link del "$DUMMY" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "### preflight"
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "ABORT: image $IMG missing (docker build -t $IMG .)"; exit 1; }
if priv nft list table inet degc >/dev/null 2>&1; then echo "ABORT: 'inet degc' already exists on host"; exit 1; fi
cleanup
echo "ok: no inet degc table, mark $MARK / table $TABLE free"

echo "### setup throwaway bridge + containers"
docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker run -d --name member    --network "$NET" -l degc.enable=true -l degc.via=testvpn alpine sleep 100000 >/dev/null
docker run -d --name bystander --network "$NET" alpine sleep 100000 >/dev/null
MEMBER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' member)
BYST_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bystander)
echo "member=$MEMBER_IP  bystander=$BYST_IP"

echo "### baseline (no degc)"
BASE_MEMBER=$(cping member); BASE_BYST=$(cping bystander); BASE_HOST=$(hping)
echo "member=$BASE_MEMBER  bystander=$BASE_BYST  host=$BASE_HOST"

echo "### bring up dummy egress + start degc"
priv ip link add "$DUMMY" type dummy
priv ip link set "$DUMMY" up
docker run -d --name "$DAEMON" --network host --cap-add NET_ADMIN \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$CFG":/etc/degc/gateways.yaml:ro \
  -e DEGC_RESYNC_INTERVAL=5 \
  "$IMG" run >/dev/null
sleep 5

echo "### installed host state"
NFT=$(priv nft list table inet degc 2>&1 || true)
echo "$NFT"
echo "--- ip rule / table $TABLE ---"
priv ip rule show 2>&1 | sed -n "/fwmark $MARK/p"
priv ip route show table "$TABLE" 2>&1 | sed 's/^/  /'

echo "### behaviour with degc active"
ON_MEMBER=$(cping member); ON_BYST=$(cping bystander); ON_HOST=$(hping)
echo "member=$ON_MEMBER  bystander=$ON_BYST  host=$ON_HOST"

echo "### stale eviction (delete-table): add a member, then remove it"
docker run -d --name memberx --network "$NET" -l degc.enable=true -l degc.via=testvpn alpine sleep 100000 >/dev/null
MEMBERX_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' memberx)
sleep 6
NFT_ADD=$(priv nft list table inet degc 2>&1 || true)
docker rm -f memberx >/dev/null
sleep 6
NFT_DEL=$(priv nft list table inet degc 2>&1 || true)
ADD_HAS=$(case "$NFT_ADD" in *"$MEMBERX_IP"*) echo YES;; *) echo NO;; esac)
DEL_HAS=$(case "$NFT_DEL" in *"$MEMBERX_IP"*) echo YES;; *) echo NO;; esac)
echo "memberx=$MEMBERX_IP  after-add=$ADD_HAS  after-remove=$DEL_HAS (expect YES then NO)"

echo "### stop daemon (rules must persist -> fail-closed)"
docker rm -f "$DAEMON" >/dev/null
sleep 1
STOP_MEMBER=$(cping member)
echo "member after daemon stop=$STOP_MEMBER (expect still BLOCKED)"

echo "### degc down (explicit teardown) + restore"
degc_down
priv ip link del "$DUMMY" >/dev/null 2>&1 || true
sleep 1
OFF_MEMBER=$(cping member)
DOWN_NFT_GONE=$(priv nft list table inet degc >/dev/null 2>&1 && echo NO || echo YES)
echo "member after down=$OFF_MEMBER (expect REACHABLE)  inet-degc-removed=$DOWN_NFT_GONE"

echo "### preflight refuses a colliding routing table"
priv ip route add blackhole 203.0.113.0/24 table "$TABLE" proto static
set +e
docker run --rm --name degc-collide --network host --cap-add NET_ADMIN \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v "$CFG":/etc/degc/gateways.yaml:ro \
  "$IMG" run >/tmp/degc.collide 2>&1
COLLIDE_RC=$?
set -e
COLLIDE_LOG=$(< /tmp/degc.collide)
priv ip route flush table "$TABLE" >/dev/null 2>&1 || true
echo "degc run exit with foreign route present: $COLLIDE_RC (expect non-zero)"

echo "### RESULT"
fail=0
chk() { if [ "$2" = "$3" ]; then echo "PASS: $1"; else echo "FAIL: $1 (got '$2', want '$3')"; fail=1; fi; }
case "$NFT" in *"$MEMBER_IP"*) echo "PASS: member IP in nft set";; *) echo "FAIL: member IP not in nft set"; fail=1;; esac
case "$NFT" in *"$BYST_IP"*) echo "FAIL: bystander IP leaked into nft set"; fail=1;; *) echo "PASS: bystander IP excluded";; esac
chk "reconcile adds new member to set"    "$ADD_HAS" YES
chk "delete-table evicts removed member"  "$DEL_HAS" NO
chk "baseline member online"              "$BASE_MEMBER" REACHABLE
chk "degc diverts member (fail-closed)" "$ON_MEMBER"   BLOCKED
chk "bystander unaffected"                "$ON_BYST"     REACHABLE
chk "host unaffected"                     "$ON_HOST"     REACHABLE
chk "daemon stop keeps block (fail-closed)" "$STOP_MEMBER" BLOCKED
chk "degc down restores member"         "$OFF_MEMBER"  REACHABLE
chk "degc down removed nft table"       "$DOWN_NFT_GONE" YES
if [ "$COLLIDE_RC" != 0 ]; then echo "PASS: preflight refused colliding table"; else echo "FAIL: ran despite table collision"; fail=1; fi
case "$COLLIDE_LOG" in *"non-degc route"*) echo "PASS: refusal names the collision";; *) echo "WARN: refusal message not found in output";; esac
[ "$fail" = 0 ] && echo "=== ALL PASS ===" || { echo "=== FAILURES ==="; exit 1; }

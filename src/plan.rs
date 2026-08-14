// SPDX-License-Identifier: MIT
//! The compiled desired state: per gateway, the resolved egress and the set of
//! member container addresses whose egress degc routes through it. Rebuilt
//! from scratch every reconcile from the current Docker snapshot (stateless;
//! see `docs/architecture.md`), so a gateway container's dynamic IP is always
//! the current one and stale members never survive.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::api::v1alpha1::{
    Gateway, Gateways, discovered_gateway, gateway_name, opt_in, selector_matches,
};
use crate::docker::Target;

/// The egress resolved against the current snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Egress {
    /// Route out a host interface (`default dev <if>`).
    Interface(String),
    /// Route via a next-hop address — a static `nextHop`, or a gateway
    /// container's *current* address (re-resolved every reconcile).
    NextHop(IpAddr),
    /// The egress could not be resolved (e.g. the gateway container isn't
    /// running). No route is installed → the gateway is fail-closed: marked
    /// traffic hits the blackhole and is dropped, never leaking.
    Unavailable(String),
}

/// A gateway plus its resolved egress and the member addresses to route.
pub struct GatewayPlan {
    pub gateway: Gateway,
    pub egress: Egress,
    pub members: BTreeSet<IpAddr>,
    /// Member container names, for `status` (which app is routed here). The
    /// nft set uses `members` (IPs); this is display-only.
    pub member_names: BTreeSet<String>,
}

/// The whole desired plan.
pub struct Plan {
    pub gateways: Vec<GatewayPlan>,
    /// `(container, requested gateway)` pairs that opted in but named no known
    /// gateway — surfaced so a typo is visible rather than silently unrouted.
    pub unresolved: Vec<(String, String)>,
    /// `(container, [gateways])` matched by more than one gateway selector with
    /// no explicit `degc.via` — ambiguous, so not routed (surfaced, not guessed).
    pub conflicts: Vec<(String, Vec<String>)>,
    /// Self-declared gateway containers whose knob labels were malformed and
    /// were dropped (fail-closed) — one message each.
    pub discovery_errors: Vec<String>,
}

/// Compile the current containers + gateways into the desired [`Plan`]. The
/// gateway set is the explicit config PLUS any container advertising itself via
/// `<prefix>.gateway: <name>` (so `gateways.yaml` is optional); an explicit
/// config entry wins on a name clash.
#[must_use]
pub fn compile(targets: &[Target], prefix: &str, gateways: &Gateways) -> Plan {
    // Merge explicit config with self-declaring gateway containers. A malformed
    // knob label drops that gateway (surfaced) rather than mis-routing.
    let mut merged: Vec<Gateway> = gateways.0.clone();
    let mut discovery_errors = Vec::new();
    for t in targets {
        let Some(name) = gateway_name(prefix, &t.labels) else {
            continue;
        };
        if merged.iter().any(|g| g.name == name) {
            continue; // explicit config wins
        }
        let egress_container = t
            .labels
            .get("com.docker.compose.service")
            .cloned()
            .unwrap_or_else(|| t.name.clone());
        match discovered_gateway(prefix, name, egress_container, &t.labels) {
            Ok(gw) => merged.push(gw),
            Err(e) => discovery_errors.push(format!("gateway container {:?}: {e:#}", t.name)),
        }
    }
    let merged = Gateways(merged);

    // Assign each non-gateway container to a gateway. Precedence: an explicit
    // `degc.enable`/`degc.via` opt-in wins; otherwise a gateway `members`
    // selector may claim it. Matching >1 gateway by selector with no explicit
    // choice is a conflict — surfaced, not routed (never guess an egress).
    let mut members: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
    let mut member_names: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut unresolved = Vec::new();
    let mut conflicts = Vec::new();
    for t in targets {
        if gateway_name(prefix, &t.labels).is_some() {
            continue; // a gateway is never its own member
        }
        if let Some(via) = opt_in(prefix, &t.labels) {
            match merged.resolve(via.as_deref()) {
                Some(gw) => add_member(&mut members, &mut member_names, &gw.name, t),
                None => unresolved.push((
                    t.name.clone(),
                    via.unwrap_or_else(|| "<default>".to_owned()),
                )),
            }
            continue;
        }
        let matched: Vec<&str> = merged
            .0
            .iter()
            .filter(|g| g.members.iter().any(|s| selector_matches(s, &t.labels)))
            .map(|g| g.name.as_str())
            .collect();
        match matched.as_slice() {
            [] => {}
            [one] => add_member(&mut members, &mut member_names, one, t),
            many => conflicts.push((
                t.name.clone(),
                many.iter().map(|s| (*s).to_owned()).collect(),
            )),
        }
    }

    let gateways = merged
        .0
        .into_iter()
        .map(|gw| {
            let egress = resolve_egress(&gw, targets);
            let member_names = member_names.remove(&gw.name).unwrap_or_default();
            let members = members.remove(&gw.name).unwrap_or_default();
            GatewayPlan {
                gateway: gw,
                egress,
                members,
                member_names,
            }
        })
        .collect();

    Plan {
        gateways,
        unresolved,
        conflicts,
        discovery_errors,
    }
}

/// Add a container's addresses (for the nft set) and name (for `status`) to a
/// gateway's member sets.
fn add_member(
    members: &mut BTreeMap<String, BTreeSet<IpAddr>>,
    names: &mut BTreeMap<String, BTreeSet<String>>,
    gw: &str,
    t: &Target,
) {
    members
        .entry(gw.to_owned())
        .or_default()
        .extend(t.networks.values().flatten().copied());
    names
        .entry(gw.to_owned())
        .or_default()
        .insert(t.name.clone());
}

/// Resolve a gateway's egress against the snapshot. A `container` egress becomes
/// that container's current address, or [`Egress::Unavailable`] if it isn't
/// running (fail-closed).
fn resolve_egress(gw: &Gateway, targets: &[Target]) -> Egress {
    if let Some(iface) = &gw.egress.interface {
        return Egress::Interface(iface.clone());
    }
    if let Some(nh) = &gw.egress.next_hop {
        return nh.parse().map_or_else(
            |_| Egress::Unavailable(format!("nextHop {nh:?} is not an IP")),
            Egress::NextHop,
        );
    }
    if let Some(sel) = &gw.egress.container {
        return match gateway_container_ip(sel, targets) {
            Some(ip) => Egress::NextHop(ip),
            None => Egress::Unavailable(format!("gateway container {sel:?} not running")),
        };
    }
    Egress::Unavailable("no egress configured".to_owned())
}

/// Find the current address of the gateway container identified by `sel` (its
/// Docker name or its Compose service label). IPv4 only — degc routes IPv4, so
/// a v6-only gateway resolves to `None` → `Egress::Unavailable` (fail-closed).
fn gateway_container_ip(sel: &str, targets: &[Target]) -> Option<IpAddr> {
    let is_match = |t: &&Target| {
        t.name == sel
            || t.labels
                .get("com.docker.compose.service")
                .map(String::as_str)
                == Some(sel)
    };
    let t = targets.iter().find(is_match)?;
    t.networks.values().flatten().copied().find(IpAddr::is_ipv4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::v1alpha1::parse_gateways;

    fn target(name: &str, ip: &str, labels: &[(&str, &str)]) -> Target {
        let mut networks = BTreeMap::new();
        networks.insert("services".to_owned(), vec![ip.parse().unwrap()]);
        Target {
            name: name.to_owned(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            networks,
        }
    }

    #[test]
    fn members_collected_per_gateway() {
        let gws = parse_gateways(
            "- name: vpn\n  egress: {interface: wg0}\n  mark: '0x4'\n  table: 200\n",
        )
        .unwrap();
        let targets = vec![
            target("a", "172.18.0.7", &[("degc.enable", "true")]),
            target(
                "b",
                "172.18.0.8",
                &[("degc.enable", "true"), ("degc.via", "vpn")],
            ),
            target("c", "172.18.0.9", &[]),
            target(
                "d",
                "172.18.0.10",
                &[("degc.enable", "true"), ("degc.via", "nope")],
            ),
        ];
        let plan = compile(&targets, "degc", &gws);
        assert_eq!(plan.gateways[0].members.len(), 2);
        assert_eq!(plan.gateways[0].egress, Egress::Interface("wg0".to_owned()));
        assert_eq!(plan.unresolved, vec![("d".to_owned(), "nope".to_owned())]);
    }

    #[test]
    fn container_egress_resolves_live_ip_or_fails_closed() {
        let gws = parse_gateways(
            "- name: gw\n  egress: {container: gluetun}\n  mark: '4'\n  table: 200\n",
        )
        .unwrap();

        // gluetun running → resolves to its current IP
        let up = vec![target(
            "gluetun",
            "172.18.0.50",
            &[("com.docker.compose.service", "gluetun")],
        )];
        assert_eq!(
            compile(&up, "degc", &gws).gateways[0].egress,
            Egress::NextHop("172.18.0.50".parse().unwrap())
        );

        // gluetun absent → fail-closed (Unavailable, no route)
        let down: Vec<Target> = vec![];
        assert!(matches!(
            compile(&down, "degc", &gws).gateways[0].egress,
            Egress::Unavailable(_)
        ));
    }

    #[test]
    fn gateway_container_self_declares_via_label() {
        // no gateways.yaml — the gateway container advertises itself.
        let gws = Gateways::default();
        let targets = vec![
            target(
                "gluetun",
                "172.18.0.24",
                &[
                    ("degc.gateway", "vpn"),
                    ("com.docker.compose.service", "vpn-gw"),
                ],
            ),
            target(
                "app",
                "172.18.0.30",
                &[("degc.enable", "true"), ("degc.via", "vpn")],
            ),
        ];
        let plan = compile(&targets, "degc", &gws);
        assert_eq!(plan.gateways.len(), 1);
        let gp = &plan.gateways[0];
        assert_eq!(gp.gateway.name, "vpn");
        assert_eq!(gp.egress, Egress::NextHop("172.18.0.24".parse().unwrap()));
        assert_eq!(
            gp.members.len(),
            1,
            "the app is routed via the discovered gateway"
        );
        assert!(plan.unresolved.is_empty());
    }

    #[test]
    fn selector_selects_members_without_optin() {
        let gws = parse_gateways(
            "- name: vpn\n  egress: {interface: wg0}\n  members:\n    - com.docker.compose.service: sabnzbd\n",
        )
        .unwrap();
        let targets = vec![
            target(
                "sab",
                "172.18.0.5",
                &[("com.docker.compose.service", "sabnzbd")],
            ),
            target(
                "plex",
                "172.18.0.6",
                &[("com.docker.compose.service", "plex")],
            ),
        ];
        let plan = compile(&targets, "degc", &gws);
        assert_eq!(
            plan.gateways[0].members.len(),
            1,
            "selector-matched app routed"
        );
        assert!(plan.gateways[0].member_names.contains("sab"));
        assert!(plan.unresolved.is_empty() && plan.conflicts.is_empty());
    }

    #[test]
    fn explicit_optin_wins_over_selector() {
        let gws = parse_gateways(
            "- name: vpn\n  egress: {interface: wg0}\n  members:\n    - vpn: 'true'\n- name: work\n  egress: {interface: wg1}\n",
        )
        .unwrap();
        let t = vec![target(
            "app",
            "172.18.0.5",
            &[
                ("vpn", "true"),
                ("degc.enable", "true"),
                ("degc.via", "work"),
            ],
        )];
        let plan = compile(&t, "degc", &gws);
        let vpn = plan
            .gateways
            .iter()
            .find(|g| g.gateway.name == "vpn")
            .unwrap();
        let work = plan
            .gateways
            .iter()
            .find(|g| g.gateway.name == "work")
            .unwrap();
        assert_eq!(vpn.members.len(), 0, "selector yields to explicit opt-in");
        assert_eq!(work.members.len(), 1);
    }

    #[test]
    fn ambiguous_selector_is_conflict_not_routed() {
        let gws = parse_gateways(
            "- name: vpn\n  egress: {interface: wg0}\n  members:\n    - app: 'yes'\n- name: work\n  egress: {interface: wg1}\n  members:\n    - app: 'yes'\n",
        )
        .unwrap();
        let t = vec![target("x", "172.18.0.5", &[("app", "yes")])];
        let plan = compile(&t, "degc", &gws);
        assert!(
            plan.gateways.iter().all(|g| g.members.is_empty()),
            "not routed on ambiguity"
        );
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].0, "x");
    }

    #[test]
    fn gateway_container_is_not_its_own_member() {
        let gws = parse_gateways(
            "- name: work\n  egress: {interface: wg1}\n  members:\n    - kind: 'router'\n",
        )
        .unwrap();
        let targets = vec![target(
            "gw",
            "172.18.0.24",
            &[
                ("degc.gateway", "vpn"),
                ("kind", "router"),
                ("com.docker.compose.service", "vpn-gw"),
            ],
        )];
        let plan = compile(&targets, "degc", &gws);
        let work = plan
            .gateways
            .iter()
            .find(|g| g.gateway.name == "work")
            .unwrap();
        assert!(
            work.members.is_empty(),
            "a gateway container is never a member"
        );
    }

    #[test]
    fn gateway_label_defines_and_selects() {
        // both features end to end: a self-declared gateway with a `members`
        // label selects an app with no opt-in and no gateways.yaml.
        let gws = Gateways::default();
        let targets = vec![
            target(
                "gw",
                "172.18.0.24",
                &[
                    ("degc.gateway", "vpn"),
                    ("degc.gateway.members", "vpn=true"),
                    ("com.docker.compose.service", "vpn-gw"),
                ],
            ),
            target("app", "172.18.0.30", &[("vpn", "true")]),
        ];
        let plan = compile(&targets, "degc", &gws);
        let vpn = plan
            .gateways
            .iter()
            .find(|g| g.gateway.name == "vpn")
            .unwrap();
        assert_eq!(vpn.members.len(), 1, "label-selector routed the app");
        assert!(vpn.member_names.contains("app"));
        assert!(plan.discovery_errors.is_empty());
    }

    #[test]
    fn discovered_knob_labels_reflected() {
        let gws = Gateways::default();
        let targets = vec![target(
            "gw",
            "172.18.0.24",
            &[
                ("degc.gateway", "vpn"),
                ("degc.gateway.snat", "true"),
                ("degc.gateway.table", "222"),
            ],
        )];
        let plan = compile(&targets, "degc", &gws);
        let gp = &plan.gateways[0];
        assert_eq!(gp.gateway.table_id(), 222);
        assert!(gp.gateway.snat_enabled());
        assert!(plan.discovery_errors.is_empty());
    }

    #[test]
    fn malformed_knob_drops_gateway_surfaced() {
        let gws = Gateways::default();
        let targets = vec![target(
            "gw",
            "172.18.0.24",
            &[
                ("degc.gateway", "vpn"),
                ("degc.gateway.table", "notanumber"),
            ],
        )];
        let plan = compile(&targets, "degc", &gws);
        assert!(plan.gateways.is_empty(), "malformed gateway dropped");
        assert_eq!(plan.discovery_errors.len(), 1);
    }
}

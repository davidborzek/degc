// SPDX-License-Identifier: MIT
//! `v1alpha1` gateway-config model, label convention, and parsing.
//!
//! A **gateway** is an egress target plus routing knobs — degc routes marked
//! traffic there but never runs the VPN itself (see `docs/architecture.md`).
//! Containers opt in with `degc.enable` / `degc.via` labels (label-spec
//! v1alpha1). Parsing is strict (`deny_unknown_fields`) so a mistyped key is a
//! hard error rather than a silently weaker config.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{Context, Result, ensure};
use ipnetwork::IpNetwork;
use serde::Deserialize;

/// This module's API version (maturity ladder `v1alpha1` → `v1beta1` → `v1`).
pub const VERSION: &str = "v1alpha1";

/// Where a gateway sends marked traffic — exactly one kind must be set
/// (checked by [`Gateway::validate`]):
///
/// - `interface` — a host interface (`wg0`), stable.
/// - `container` — a gateway container by name / Compose service; degc
///   resolves its **current** address every reconcile (dynamic-IP safe). Absent
///   at reconcile time → fail-closed (no route installed).
/// - `nextHop` — a static next-hop IP; only for a genuinely stable gateway (a
///   physical router), never a container.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Egress {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub container: Option<String>,
    #[serde(default)]
    pub next_hop: Option<String>,
}

/// A label selector: a container matches when it carries **every** listed
/// label with the given value (AND within a selector). Follows the label-spec
/// `selector` shape (see `LABEL-SPEC.md`). An empty
/// selector matches nothing (never "all containers" — that would be a
/// catastrophic accidental route for a privacy tool).
pub type Selector = BTreeMap<String, String>;

/// A gateway: an egress target + its routing knobs. Carries no VPN parameters
/// and no secrets — the tunnel is provided externally.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Gateway {
    /// Gateway name, referenced by `degc.via`.
    pub name: String,
    /// Where marked traffic egresses.
    pub egress: Egress,
    /// Masquerade onto the egress. Optional — defaults to `true` for an
    /// `interface` egress (a host wg device needs it) and `false` otherwise
    /// (a gateway container masquerades onto the tunnel itself).
    #[serde(default)]
    pub snat: Option<bool>,
    /// Firewall mark, e.g. `"0x4"`. Optional — auto-derived from the gateway
    /// name (stable) when unset; only set it to resolve a rare collision.
    #[serde(default)]
    pub mark: Option<String>,
    /// Policy-routing table id. Optional — auto-derived from the gateway name
    /// when unset; only set it to resolve a rare collision.
    #[serde(default)]
    pub table: Option<u32>,
    /// Make this the gateway used when a container sets `degc.enable` without
    /// `degc.via`. At most one gateway may be the default.
    #[serde(default)]
    pub default: bool,
    /// Destinations that stay DIRECT (never tunnelled) — the flat Docker nets +
    /// the LAN. Optional — defaults to the RFC1918 ranges when empty.
    #[serde(default)]
    pub local_subnets: Vec<String>,
    /// Containers matched by ANY of these selectors are routed via this gateway
    /// **without** a per-container `degc.enable` label — central
    /// selection. Explicit opt-in still wins; a container matching two
    /// gateways' selectors is a conflict (surfaced, not routed). Empty =
    /// selector membership off (explicit opt-in only).
    #[serde(default)]
    pub members: Vec<Selector>,
}

impl Gateway {
    /// The effective fwmark: the explicit value, or one auto-derived from the
    /// gateway name (stable across restarts).
    ///
    /// # Errors
    /// Fails if an explicit mark isn't a valid decimal / `0x`-hex `u32`.
    pub fn mark_value(&self) -> Result<u32> {
        match &self.mark {
            Some(m) => {
                parse_mark(m).with_context(|| format!("gateway {}: bad mark {m:?}", self.name))
            }
            None => Ok(auto_mark(&self.name)),
        }
    }

    /// The effective routing-table id (explicit, or auto-derived from the name).
    #[must_use]
    pub fn table_id(&self) -> u32 {
        self.table.unwrap_or_else(|| auto_table(&self.name))
    }

    /// Whether to masquerade onto the egress — explicit, or inferred: `true` for
    /// an `interface` egress, `false` for a container / next-hop gateway.
    #[must_use]
    pub fn snat_enabled(&self) -> bool {
        self.snat.unwrap_or_else(|| self.egress.interface.is_some())
    }

    /// Local (direct, never-tunnelled) subnets — the configured ones, or the
    /// RFC1918 defaults when none are given.
    #[must_use]
    pub fn local_subnets_effective(&self) -> Vec<String> {
        if self.local_subnets.is_empty() {
            DEFAULT_LOCAL_SUBNETS
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        } else {
            self.local_subnets.clone()
        }
    }

    /// Validate a single gateway: exactly one egress kind; any explicit mark /
    /// table / next-hop / local subnets well-formed.
    ///
    /// # Errors
    /// Fails on any malformed or contradictory field.
    pub fn validate(&self) -> Result<()> {
        let ctx = || format!("gateway {}", self.name);
        let kinds = [
            self.egress.interface.is_some(),
            self.egress.container.is_some(),
            self.egress.next_hop.is_some(),
        ];
        let n = kinds.iter().filter(|set| **set).count();
        ensure!(
            n == 1,
            "{}: egress needs exactly one of interface/container/nextHop (got {n})",
            ctx()
        );
        if let Some(m) = &self.mark {
            let v = parse_mark(m).with_context(|| format!("{}: bad mark {m:?}", ctx()))?;
            ensure!(
                v != 0,
                "{}: mark must be non-zero (0 matches all unmarked traffic)",
                ctx()
            );
        }
        if let Some(t) = self.table {
            ensure!(t > 0, "{}: table must be > 0", ctx());
        }
        if let Some(iface) = &self.egress.interface {
            ensure!(
                valid_ifname(iface),
                "{}: bad interface name {iface:?} (want 1-15 of [A-Za-z0-9._-])",
                ctx()
            );
        }
        if let Some(nh) = &self.egress.next_hop {
            IpAddr::from_str(nh).with_context(|| format!("{}: bad nextHop {nh:?}", ctx()))?;
        }
        for s in &self.local_subnets {
            IpNetwork::from_str(s).with_context(|| format!("{}: bad localSubnet {s:?}", ctx()))?;
        }
        for sel in &self.members {
            ensure!(
                !sel.is_empty(),
                "{}: a members selector must not be empty (it would match nothing)",
                ctx()
            );
        }
        Ok(())
    }
}

/// RFC1918 private ranges — the default `local_subnets` (stay direct).
const DEFAULT_LOCAL_SUBNETS: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// Stable fwmark auto-derived from the gateway name (16-bit range, non-zero).
fn auto_mark(name: &str) -> u32 {
    0x1000 + (fnv1a(name) % 0xE000)
}

/// Stable routing-table id auto-derived from the gateway name (5000–5999).
fn auto_table(name: &str) -> u32 {
    5000 + (fnv1a(name) % 1000)
}

/// FNV-1a 32-bit hash — stable across builds (unlike `DefaultHasher`) so a
/// gateway's auto-derived mark/table never change.
fn fnv1a(s: &str) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in s.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// Whether `name` is a plausible network-interface name that's safe to
/// interpolate into the nft ruleset (1-15 chars of `[A-Za-z0-9._-]`).
fn valid_ifname(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The parsed gateways document plus the resolution rules over it.
#[derive(Debug, Clone, Default)]
pub struct Gateways(pub Vec<Gateway>);

impl Gateways {
    /// Validate the whole set: each gateway, unique names, ≤1 default.
    ///
    /// # Errors
    /// Fails on a malformed gateway, a duplicate name, or >1 default.
    pub fn validate(&self) -> Result<()> {
        let mut seen = BTreeMap::new();
        let mut defaults = 0usize;
        for gw in &self.0 {
            gw.validate()?;
            ensure!(
                seen.insert(&gw.name, ()).is_none(),
                "duplicate gateway {:?}",
                gw.name
            );
            defaults += usize::from(gw.default);
        }
        ensure!(defaults <= 1, "more than one default gateway");
        check_unique_routing(self.0.iter())?;
        Ok(())
    }

    /// Resolve a `degc.via` value (or `None` for "the default") to a gateway.
    /// A single configured gateway is the default even without `default: true`.
    #[must_use]
    pub fn resolve(&self, via: Option<&str>) -> Option<&Gateway> {
        match via {
            Some(name) => self.0.iter().find(|g| g.name == name),
            None => self.0.iter().find(|g| g.default).or(if self.0.len() == 1 {
                self.0.first()
            } else {
                None
            }),
        }
    }
}

/// Ensure no two gateways share an effective fwmark or routing table. An
/// auto-derived (name-hash) *or* hand-set collision would policy-route one
/// gateway's members out another's egress — a fail-open leak for container /
/// next-hop egress (no host oif kill-switch there). Checked over the merged set
/// (config + label-discovered) every reconcile, so it fails closed.
///
/// # Errors
/// Fails on a shared mark or table, or an unparseable explicit mark.
pub fn check_unique_routing<'a>(gateways: impl IntoIterator<Item = &'a Gateway>) -> Result<()> {
    let mut marks: BTreeMap<u32, &str> = BTreeMap::new();
    let mut tables: BTreeMap<u32, &str> = BTreeMap::new();
    for gw in gateways {
        let mark = gw.mark_value()?;
        if let Some(other) = marks.insert(mark, gw.name.as_str()) {
            anyhow::bail!(
                "gateways {other:?} and {:?} resolve to the same mark 0x{mark:x} — set an explicit `mark` on one",
                gw.name
            );
        }
        let table = gw.table_id();
        if let Some(other) = tables.insert(table, gw.name.as_str()) {
            anyhow::bail!(
                "gateways {other:?} and {:?} resolve to the same table {table} — set an explicit `table` on one",
                gw.name
            );
        }
    }
    Ok(())
}

/// Parse a gateways document (a YAML list of [`Gateway`]).
///
/// # Errors
/// Fails if the document is not a valid list of gateways (incl. unknown keys).
pub fn parse_gateways(text: &str) -> Result<Gateways> {
    let gws: Vec<Gateway> = serde_yaml_ng::from_str(text).context("parse gateways document")?;
    let gws = Gateways(gws);
    gws.validate()?;
    Ok(gws)
}

/// Whether a container opts into degc and which gateway it names.
///
/// Returns `None` when not opted in; `Some(None)` for `degc.enable` with no
/// `degc.via` (use the default gateway); `Some(Some(g))` for `degc.via: g`.
#[must_use]
pub fn opt_in(prefix: &str, labels: &BTreeMap<String, String>) -> Option<Option<String>> {
    let enabled = labels.get(&format!("{prefix}.enable")).map(String::as_str) == Some("true");
    if !enabled {
        return None;
    }
    Some(labels.get(&format!("{prefix}.via")).cloned())
}

/// The gateway name a container *advertises* via `<prefix>.gateway: <name>` — a
/// gateway container declaring itself, so no `gateways.yaml` entry is needed.
/// Returns `None` when the label is absent or empty.
#[must_use]
pub fn gateway_name(prefix: &str, labels: &BTreeMap<String, String>) -> Option<String> {
    labels
        .get(&format!("{prefix}.gateway"))
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Whether a container's `labels` satisfy `selector` (every key present with
/// the given value). An empty selector never matches.
#[must_use]
pub fn selector_matches(selector: &Selector, labels: &BTreeMap<String, String>) -> bool {
    !selector.is_empty() && selector.iter().all(|(k, v)| labels.get(k) == Some(v))
}

/// Parse a `<prefix>.gateway.members` label — comma-separated `key=value` pairs
/// forming a single [`Selector`] (e.g. `"vpn=true,tier=dl"`).
fn parse_selector_label(s: &str) -> Selector {
    s.split(',')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect()
}

/// Build a self-declared gateway from a gateway container's labels: the `name`
/// (from `<prefix>.gateway`), the container itself as egress, plus optional
/// `<prefix>.gateway.<field>` knobs — `snat`, `mark`, `table`, `localSubnets`
/// (comma list), `default`, `members` (one selector). Returned validated, so a
/// malformed knob is a hard error the caller surfaces and drops the gateway
/// (fail-closed: its would-be members go unrouted, never mis-routed).
///
/// # Errors
/// Fails on an unparseable `table` label or any [`Gateway::validate`] failure.
pub fn discovered_gateway(
    prefix: &str,
    name: String,
    egress_container: String,
    labels: &BTreeMap<String, String>,
) -> Result<Gateway> {
    let field = |f: &str| {
        labels
            .get(&format!("{prefix}.gateway.{f}"))
            .map(|s| s.trim())
    };
    let snat = match field("snat") {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    };
    let table = field("table")
        .map(|t| {
            t.parse::<u32>()
                .with_context(|| format!("gateway {name:?}: bad table label {t:?}"))
        })
        .transpose()?;
    let local_subnets = field("localSubnets").map_or_else(Vec::new, |s| {
        s.split(',')
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .collect()
    });
    let members = field("members").map_or_else(Vec::new, |s| vec![parse_selector_label(s)]);
    let gw = Gateway {
        name,
        egress: Egress {
            container: Some(egress_container),
            ..Egress::default()
        },
        snat,
        mark: field("mark").map(str::to_owned),
        table,
        default: field("default") == Some("true"),
        local_subnets,
        members,
    };
    gw.validate()?;
    Ok(gw)
}

/// Parse `"0x4"` / `"4"` into a `u32`.
fn parse_mark(s: &str) -> Result<u32> {
    let s = s.trim();
    let v = s.strip_prefix("0x").map_or_else(
        || s.parse::<u32>().ok(),
        |hex| u32::from_str_radix(hex, 16).ok(),
    );
    v.ok_or_else(|| anyhow::anyhow!("not a u32: {s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn mark_parses_hex_and_dec() {
        assert_eq!(parse_mark("0x4").unwrap(), 4);
        assert_eq!(parse_mark("16").unwrap(), 16);
        assert!(parse_mark("zz").is_err());
    }

    #[test]
    fn opt_in_semantics() {
        assert_eq!(opt_in("degc", &labels(&[])), None);
        assert_eq!(opt_in("degc", &labels(&[("degc.enable", "false")])), None);
        assert_eq!(
            opt_in("degc", &labels(&[("degc.enable", "true")])),
            Some(None)
        );
        assert_eq!(
            opt_in(
                "degc",
                &labels(&[("degc.enable", "true"), ("degc.via", "vpn")])
            ),
            Some(Some("vpn".to_owned()))
        );
    }

    #[test]
    fn gateway_validation() {
        let ok = parse_gateways(
            "- name: vpn\n  egress: {interface: wg0}\n  snat: true\n  mark: '0x4'\n  table: 200\n  localSubnets: ['192.168.0.0/16']\n",
        )
        .unwrap();
        assert_eq!(ok.0.len(), 1);
        assert!(ok.resolve(None).is_some(), "sole gateway is the default");
        assert_eq!(ok.resolve(Some("nope")), None);

        // container egress is valid (resolved at reconcile)
        assert!(
            parse_gateways("- name: c\n  egress: {container: gluetun}\n  mark: '1'\n  table: 1\n")
                .is_ok()
        );
        // two egress kinds -> error
        assert!(
            parse_gateways(
                "- name: x\n  egress: {interface: a, nextHop: 10.0.0.1}\n  mark: '1'\n  table: 1\n"
            )
            .is_err()
        );
        // no egress kind -> error
        assert!(parse_gateways("- name: x\n  egress: {}\n  mark: '1'\n  table: 1\n").is_err());
        // unknown key -> hard error
        assert!(
            parse_gateways(
                "- name: x\n  egress: {interface: a}\n  mark: '1'\n  table: 1\n  bogus: 1\n"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_zero_mark_and_bad_interface() {
        // mark 0 would match all unmarked traffic (catastrophic kill-switch)
        assert!(
            parse_gateways("- name: x\n  egress: {interface: wg0}\n  mark: '0'\n  table: 1\n")
                .is_err()
        );
        assert!(
            parse_gateways("- name: x\n  egress: {interface: wg0}\n  mark: '0x0'\n  table: 1\n")
                .is_err()
        );
        // interface names that could break the nft script
        assert!(
            parse_gateways("- name: x\n  egress: {interface: 'a\"b'}\n  mark: '1'\n  table: 1\n")
                .is_err()
        );
        assert!(
            parse_gateways(
                "- name: x\n  egress: {interface: thisnameiswaytoolong}\n  mark: '1'\n  table: 1\n"
            )
            .is_err()
        );
        // a normal wg interface name is fine
        assert!(
            parse_gateways("- name: x\n  egress: {interface: wg0}\n  mark: '1'\n  table: 1\n")
                .is_ok()
        );
    }

    #[test]
    fn minimal_config_needs_no_numbers() {
        // the whole point: a gateway is just a name + an egress — no mark/table/snat.
        let gws = parse_gateways("- name: vpn\n  egress: {container: vpn-gw}\n").unwrap();
        let gw = &gws.0[0];
        // mark auto-derived: stable, non-zero, in the 16-bit range.
        let m = gw.mark_value().unwrap();
        assert_ne!(m, 0);
        assert!((0x1000..=0xFFFF).contains(&m), "auto mark in range: {m:#x}");
        assert_eq!(m, gw.mark_value().unwrap(), "auto mark is stable");
        // table auto-derived into a private range.
        assert!(
            (5000..=5999).contains(&gw.table_id()),
            "auto table: {}",
            gw.table_id()
        );
        // snat inferred: container egress → no snat (the gateway masquerades).
        assert!(!gw.snat_enabled());
        // localSubnets default to RFC1918.
        assert_eq!(
            gw.local_subnets_effective(),
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        );
    }

    #[test]
    fn snat_inferred_from_egress_and_overridable() {
        // interface egress → snat on by default (host wg needs it).
        let iface = parse_gateways("- name: m\n  egress: {interface: wg0}\n").unwrap();
        assert!(iface.0[0].snat_enabled());
        // explicit override wins.
        let off = parse_gateways("- name: m\n  egress: {interface: wg0}\n  snat: false\n").unwrap();
        assert!(!off.0[0].snat_enabled());
    }

    #[test]
    fn distinct_names_get_distinct_auto_values() {
        let a = parse_gateways("- name: vpn\n  egress: {container: x}\n").unwrap();
        let b = parse_gateways("- name: work\n  egress: {container: y}\n").unwrap();
        assert_ne!(a.0[0].mark_value().unwrap(), b.0[0].mark_value().unwrap());
        assert_ne!(a.0[0].table_id(), b.0[0].table_id());
    }

    #[test]
    fn colliding_auto_routing_is_rejected() {
        // "ac" and "bb" both auto-derive routing table 5565 — must fail closed
        // (else one gateway's members would route out the other's egress).
        let r = parse_gateways(
            "- name: ac\n  egress: {container: x}\n- name: bb\n  egress: {container: y}\n",
        );
        assert!(r.is_err(), "colliding auto tables must be rejected: {r:?}");
        // explicit distinct tables resolve it
        assert!(
            parse_gateways(
                "- name: ac\n  egress: {container: x}\n  table: 100\n- name: bb\n  egress: {container: y}\n  table: 101\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn selector_matches_all_keys_or_none() {
        let l = labels(&[("vpn", "true"), ("tier", "dl")]);
        assert!(selector_matches(&parse_selector_label("vpn=true"), &l));
        assert!(selector_matches(
            &parse_selector_label("vpn=true,tier=dl"),
            &l
        ));
        // one key wrong → no match (AND semantics)
        assert!(!selector_matches(
            &parse_selector_label("vpn=true,tier=xx"),
            &l
        ));
        // missing key → no match
        assert!(!selector_matches(&parse_selector_label("zone=eu"), &l));
        // empty selector never matches
        assert!(!selector_matches(&Selector::new(), &l));
    }

    #[test]
    fn members_selector_parses_and_validates() {
        let gws = parse_gateways(
            "- name: vpn\n  egress: {container: gw}\n  members:\n    - com.docker.compose.service: sabnzbd\n    - {vpn: 'true'}\n",
        )
        .unwrap();
        assert_eq!(gws.0[0].members.len(), 2);
        // an empty selector in the list is rejected
        assert!(
            parse_gateways("- name: vpn\n  egress: {container: gw}\n  members:\n    - {}\n")
                .is_err()
        );
    }

    #[test]
    fn discovered_gateway_reads_knobs() {
        let l = labels(&[
            ("degc.gateway", "vpn"),
            ("degc.gateway.snat", "false"),
            ("degc.gateway.table", "220"),
            ("degc.gateway.localSubnets", "10.0.0.0/8, 192.168.0.0/16"),
            ("degc.gateway.members", "vpn=true"),
        ]);
        let gw = discovered_gateway("degc", "vpn".to_owned(), "vpn-gw".to_owned(), &l).unwrap();
        assert_eq!(gw.egress.container.as_deref(), Some("vpn-gw"));
        assert!(!gw.snat_enabled(), "snat=false honored");
        assert_eq!(gw.table_id(), 220);
        assert_eq!(gw.local_subnets.len(), 2);
        assert_eq!(gw.members, vec![parse_selector_label("vpn=true")]);
    }

    #[test]
    fn discovered_gateway_bad_table_is_error() {
        let l = labels(&[("degc.gateway", "vpn"), ("degc.gateway.table", "abc")]);
        assert!(discovered_gateway("degc", "vpn".to_owned(), "gw".to_owned(), &l).is_err());
    }
}

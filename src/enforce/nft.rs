// SPDX-License-Identifier: MIT
//! Compiles a [`Plan`] into an nftables script for the `inet degc` table and
//! applies it atomically via `nft -f -` (one transaction: add-table, delete,
//! redefine). The script is exactly what `--dry-run` shows, so the kill-switch
//! is auditable. degc owns only this table and touches nothing else.
//!
//! Three base chains, one rule per gateway in each:
//! - `degc_mark` (prerouting, mangle): mark a member's non-local egress.
//! - `degc_snat` (postrouting, srcnat): masquerade onto a host wg iface (opt-in).
//! - `degc_killswitch` (forward, filter): drop marked traffic leaving the wrong
//!   interface. Belt-and-suspenders with the routing-table blackhole so an
//!   unavailable egress fails closed instead of leaking.

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use ipnetwork::IpNetwork;

use crate::plan::{Egress, Plan};

/// Idempotent teardown script for `degc down`: create-if-absent then delete,
/// so it succeeds whether or not the table currently exists.
pub const TEARDOWN_SCRIPT: &str = "add table inet degc\ndelete table inet degc\n";

/// Build the `nft -f` script for the whole plan.
///
/// # Errors
/// Fails if a gateway's mark can't be parsed.
pub fn build_script(plan: &Plan) -> Result<String> {
    let mut sets = String::new();
    let mut mark_rules = String::new();
    let mut snat_rules = String::new();
    let mut kill_rules = String::new();

    for gp in &plan.gateways {
        let gw = &gp.gateway;
        let mark = format!("0x{:x}", gw.mark_value()?);
        let via = format!("degc_via_{}", sanitize(&gw.name));

        // Member sets, split by family. IPv4 members are marked + policy-routed;
        // IPv6 is NOT routed, so a member's non-local v6 egress is dropped
        // (fail-closed) rather than leaking out unfiltered. Full v6 routing is
        // future work.
        let members4: Vec<String> = gp
            .members
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(ToString::to_string)
            .collect();
        let members6: Vec<String> = gp
            .members
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(ToString::to_string)
            .collect();
        emit_set(&mut sets, &via, "ipv4_addr", false, &members4);

        // Local-subnet exclusions (these stay direct), per family.
        let locals4: Vec<String> = gw
            .local_subnets_effective()
            .iter()
            .filter_map(|s| s.parse::<IpNetwork>().ok())
            .filter(IpNetwork::is_ipv4)
            .map(|n| n.to_string())
            .collect();
        let excl4 = excl_clause(
            &mut sets,
            &format!("degc_local_{}", sanitize(&gw.name)),
            "ipv4_addr",
            "ip daddr",
            &locals4,
        );
        let _ = writeln!(
            mark_rules,
            "        ip saddr @{via}{excl4} meta mark set {mark}"
        );

        if gw.snat_enabled() {
            match &gp.egress {
                Egress::Interface(iface) => {
                    let _ = writeln!(
                        snat_rules,
                        "        meta mark {mark} oifname \"{iface}\" masquerade"
                    );
                }
                Egress::NextHop(_) => {
                    let _ = writeln!(snat_rules, "        meta mark {mark} masquerade");
                }
                Egress::Unavailable(_) => {}
            }
        }

        // IPv6 kill-switch (only when a member actually has a v6 address).
        if !members6.is_empty() {
            let via6 = format!("degc_via6_{}", sanitize(&gw.name));
            emit_set(&mut sets, &via6, "ipv6_addr", false, &members6);
            let locals6: Vec<String> = gw
                .local_subnets_effective()
                .iter()
                .filter_map(|s| s.parse::<IpNetwork>().ok())
                .filter(IpNetwork::is_ipv6)
                .map(|n| n.to_string())
                .collect();
            let excl6 = excl_clause(
                &mut sets,
                &format!("degc_local6_{}", sanitize(&gw.name)),
                "ipv6_addr",
                "ip6 daddr",
                &locals6,
            );
            let _ = writeln!(kill_rules, "        ip6 saddr @{via6}{excl6} drop");
        }

        // IPv4 kill-switch depends on the egress kind.
        match &gp.egress {
            Egress::Interface(iface) => {
                let _ = writeln!(
                    kill_rules,
                    "        meta mark {mark} oifname != \"{iface}\" drop"
                );
            }
            Egress::Unavailable(why) => {
                let _ = writeln!(
                    kill_rules,
                    "        meta mark {mark} drop   # egress unavailable: {why}"
                );
            }
            // next-hop egress can't oif-match cleanly; the blackhole + the gateway
            // container's own kill-switch are the guard.
            Egress::NextHop(_) => {}
        }
    }

    let mut out = String::new();
    // Atomic in one `nft -f` transaction. `delete` (not `flush`) so removed set
    // elements don't linger: `flush table` leaves named-set contents in place.
    let _ = writeln!(out, "add table inet degc");
    let _ = writeln!(out, "delete table inet degc");
    let _ = writeln!(out, "table inet degc {{");
    out.push_str(&sets);
    let _ = writeln!(out, "    chain degc_mark {{");
    let _ = writeln!(
        out,
        "        type filter hook prerouting priority mangle; policy accept;"
    );
    out.push_str(&mark_rules);
    let _ = writeln!(out, "    }}");
    if !snat_rules.is_empty() {
        let _ = writeln!(out, "    chain degc_snat {{");
        let _ = writeln!(
            out,
            "        type nat hook postrouting priority srcnat; policy accept;"
        );
        out.push_str(&snat_rules);
        let _ = writeln!(out, "    }}");
    }
    let _ = writeln!(out, "    chain degc_killswitch {{");
    let _ = writeln!(
        out,
        "        type filter hook forward priority filter; policy accept;"
    );
    out.push_str(&kill_rules);
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}");
    Ok(out)
}

/// Emit an nft set definition (`elements` omitted when empty).
fn emit_set(out: &mut String, name: &str, typ: &str, interval: bool, elems: &[String]) {
    let _ = writeln!(out, "    set {name} {{");
    let _ = writeln!(out, "        type {typ}");
    if interval {
        let _ = writeln!(out, "        flags interval");
    }
    if !elems.is_empty() {
        let _ = writeln!(out, "        elements = {{ {} }}", elems.join(", "));
    }
    let _ = writeln!(out, "    }}");
}

/// Emit an interval exclusion set for `cidrs` and return the match clause
/// (` <daddr_kw> != @<name>`), or an empty string when there's nothing to exclude.
fn excl_clause(
    out: &mut String,
    name: &str,
    typ: &str,
    daddr_kw: &str,
    cidrs: &[String],
) -> String {
    if cidrs.is_empty() {
        return String::new();
    }
    emit_set(out, name, typ, true, cidrs);
    format!(" {daddr_kw} != @{name}")
}

/// Apply the ruleset atomically via `nft -f -`.
///
/// # Errors
/// Fails if `nft` can't be spawned or the transaction is rejected.
pub fn apply(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning nft (is nftables installed?)")?;
    child
        .stdin
        .take()
        .context("nft stdin unavailable")?
        .write_all(script.as_bytes())
        .context("writing ruleset to nft")?;
    let out = child.wait_with_output().context("waiting for nft")?;
    if !out.status.success() {
        bail!(
            "nft -f rejected the ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Replace characters invalid in an nftables set identifier with `_`.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::v1alpha1::{Egress as CfgEgress, Gateway};
    use crate::plan::{GatewayPlan, Plan};
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    fn gw() -> Gateway {
        Gateway {
            name: "vpn".to_owned(),
            egress: CfgEgress::default(),
            snat: Some(true),
            mark: Some("0x4".to_owned()),
            table: Some(200),
            default: false,
            local_subnets: vec!["10.0.0.0/8".to_owned(), "fd00::/8".to_owned()],
            members: vec![],
        }
    }

    fn plan_with(g: &Gateway, egress: Egress, members: BTreeSet<IpAddr>) -> Plan {
        Plan {
            gateways: vec![GatewayPlan {
                gateway: g.clone(),
                egress,
                members,
                member_names: BTreeSet::new(),
            }],
            unresolved: vec![],
            conflicts: vec![],
            discovery_errors: vec![],
        }
    }

    #[test]
    fn interface_egress_marks_snats_and_killswitches() {
        let g = gw();
        let mut members = BTreeSet::new();
        members.insert("172.18.0.7".parse::<IpAddr>().unwrap());
        members.insert("fd00::1".parse::<IpAddr>().unwrap());
        let plan = plan_with(&g, Egress::Interface("wg0".to_owned()), members);
        let s = build_script(&plan).unwrap();

        assert!(s.contains("add table inet degc"));
        assert!(
            s.contains("delete table inet degc"),
            "delete (not flush) so set elements don't linger: {s}"
        );
        // IPv4: marked + policy-routed.
        assert!(
            s.contains("elements = { 172.18.0.7 }"),
            "v4 member in the mark set: {s}"
        );
        assert!(
            s.contains("elements = { 10.0.0.0/8 }"),
            "v4 local exclusion: {s}"
        );
        assert!(s.contains("ip saddr @degc_via_vpn ip daddr != @degc_local_vpn meta mark set 0x4"));
        assert!(s.contains("meta mark 0x4 oifname \"wg0\" masquerade"));
        assert!(s.contains("meta mark 0x4 oifname != \"wg0\" drop"));
        // IPv6: fail-closed drop (never routed, never leaked).
        assert!(
            s.contains("set degc_via6_vpn"),
            "v6 member set present: {s}"
        );
        assert!(
            s.contains("elements = { fd00::1 }"),
            "v6 member captured: {s}"
        );
        assert!(
            s.contains("ip6 saddr @degc_via6_vpn ip6 daddr != @degc_local6_vpn drop"),
            "v6 kill-switch: {s}"
        );
    }

    #[test]
    fn unavailable_egress_drops_all_marked_and_has_no_snat() {
        let g = gw();
        let plan = plan_with(
            &g,
            Egress::Unavailable("gluetun not running".to_owned()),
            BTreeSet::new(),
        );
        let s = build_script(&plan).unwrap();

        assert!(s.contains("meta mark 0x4 drop"));
        assert!(!s.contains("masquerade"), "no egress to snat onto: {s}");
        assert!(!s.contains("oifname"), "no interface to match: {s}");
    }
}

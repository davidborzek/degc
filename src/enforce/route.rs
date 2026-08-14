// SPDX-License-Identifier: MIT
//! Compiles a [`Plan`] into the `ip rule` / `ip route` commands that policy-route
//! each gateway's marked traffic onto its egress, with a blackhole default so an
//! unavailable egress is fail-closed. Applied via the `ip` binary; idempotent
//! (del-then-add per rule, flush-then-add per table) so every reconcile converges
//! and a stale route can't survive.

use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::api::v1alpha1::Gateways;
use crate::plan::{Egress, Plan};

/// Route protocol tag stamped on every route degc installs. `ip route flush`
/// is scoped to it, so degc only ever removes ITS OWN routes — even if the
/// (numeric, un-arbitrated) routing-table id collides with another tool's. The
/// nft table is namespaced by name; this gives the routing side the same safety.
///
/// 194 is unassigned in iproute2's known protocols — deliberately outside the
/// system range (1–18) and the routing-daemon block (186–192: bgp/isis/ospf/
/// rip/eigrp), so it won't be confused with, or clobber, a real routing daemon.
pub const RT_PROTO: &str = "194";

/// Priority for degc's fwmark rules — a fixed low value (well below `main`'s
/// 32766), decoupled from the table id so a large table number can't push the
/// rule *after* `main` and silently disable diversion (marked traffic would then
/// leak via `main`).
pub const RULE_PRIORITY: &str = "100";

/// One `ip` invocation (the argv after the program name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCmd {
    /// Arguments passed to `ip`.
    pub args: Vec<String>,
    /// Failure is expected (a `del`/`flush` of something absent) → don't error.
    pub ignore_fail: bool,
}

impl IpCmd {
    fn new(args: &[&str], ignore_fail: bool) -> Self {
        Self {
            args: args.iter().map(ToString::to_string).collect(),
            ignore_fail,
        }
    }
}

/// Build the ordered `ip` commands for the whole plan.
///
/// # Errors
/// Fails if a gateway's mark can't be parsed.
pub fn build(plan: &Plan) -> Result<Vec<IpCmd>> {
    let mut cmds = Vec::new();
    for gp in &plan.gateways {
        let gw = &gp.gateway;
        let mark = format!("0x{:x}", gw.mark_value()?);
        let table = gw.table_id().to_string();
        let (mark, table) = (mark.as_str(), table.as_str());

        // Fail-closed floor FIRST: a permanent blackhole default, so marked
        // traffic can never fall through to `main` while we (re)install the live
        // route. `replace` is create-or-update — never an empty-table window.
        cmds.push(IpCmd::new(
            &[
                "route",
                "replace",
                "blackhole",
                "default",
                "table",
                table,
                "proto",
                RT_PROTO,
                "metric",
                "9999",
            ],
            false,
        ));
        // fwmark -> table rule at a fixed low priority. Added idempotently and
        // never removed mid-run, so there's no window where marked traffic isn't
        // diverted; an EEXIST on re-add is expected and ignored.
        cmds.push(IpCmd::new(
            &[
                "rule",
                "add",
                "fwmark",
                mark,
                "table",
                table,
                "priority",
                RULE_PRIORITY,
            ],
            true,
        ));
        // Live default (atomic replace), or remove it so only the blackhole stays.
        match &gp.egress {
            Egress::Interface(iface) => {
                cmds.push(IpCmd::new(
                    &[
                        "route", "replace", "default", "dev", iface, "table", table, "proto",
                        RT_PROTO, "metric", "1",
                    ],
                    false,
                ));
            }
            Egress::NextHop(ip) => {
                let ip = ip.to_string();
                cmds.push(IpCmd::new(
                    &[
                        "route", "replace", "default", "via", &ip, "table", table, "proto",
                        RT_PROTO, "metric", "1",
                    ],
                    false,
                ));
            }
            // Unavailable: drop any stale live default → only the blackhole remains.
            Egress::Unavailable(_) => {
                cmds.push(IpCmd::new(
                    &[
                        "route", "del", "default", "table", table, "proto", RT_PROTO, "metric", "1",
                    ],
                    true,
                ));
            }
        }
    }
    Ok(cmds)
}

/// Build the `ip` commands that remove degc's policy routing for every
/// configured gateway (used by `degc down`). All idempotent (`ignore_fail`),
/// so it's safe whether or not the rules are currently installed.
///
/// # Errors
/// Fails if a gateway's mark can't be parsed.
pub fn teardown(gateways: &Gateways) -> Result<Vec<IpCmd>> {
    let mut cmds = Vec::new();
    for gw in &gateways.0 {
        let mark = format!("0x{:x}", gw.mark_value()?);
        let table = gw.table_id().to_string();
        cmds.push(IpCmd::new(
            &[
                "rule",
                "del",
                "fwmark",
                mark.as_str(),
                "table",
                table.as_str(),
            ],
            true,
        ));
        cmds.push(IpCmd::new(
            &["route", "flush", "table", table.as_str(), "proto", RT_PROTO],
            true,
        ));
    }
    Ok(cmds)
}

/// Preflight the routing side against the live host BEFORE programming it:
/// refuse (fail-closed) if a gateway's routing table already holds a foreign
/// route, or its fwmark is already routed to a different table. The nft table is
/// namespaced by name and needs no such check. `guards` is `(mark, table)` per
/// gateway.
///
/// # Errors
/// Fails on a detected collision (with a message naming the offending entry).
pub fn preflight(guards: &[(String, u32)]) -> Result<()> {
    let rules = ip_show(&["-o", "rule", "show"]);
    for (mark, table) in guards {
        let table = table.to_string();
        let routes = ip_show(&["-o", "route", "show", "table", &table]);
        if let Some(foreign) = foreign_route(&routes) {
            bail!(
                "routing table {table} already holds a non-degc route ({foreign:?}); \
                 refusing to touch it — set a free `table` for this gateway"
            );
        }
        if let Some(rule) = conflicting_fwmark_rule(&rules, mark, &table) {
            bail!(
                "fwmark {mark} is already routed elsewhere ({rule:?}); \
                 set a free `mark` for this gateway"
            );
        }
    }
    Ok(())
}

/// Run `ip <args>` and return stdout; a non-zero exit (e.g. a table that doesn't
/// exist yet) yields an empty string — for preflight that just means "nothing
/// there", never a false collision.
fn ip_show(args: &[&str]) -> String {
    Command::new("ip")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// A non-empty route line lacking degc's `proto` tag = a foreign occupant.
fn foreign_route(routes: &str) -> Option<String> {
    let tag = format!("proto {RT_PROTO}");
    routes
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.contains(&tag))
        .map(ToOwned::to_owned)
}

/// An `ip rule` that matches our `mark` but looks up a *different* table — i.e.
/// someone else already owns this fwmark. Our own rule (same mark → same table)
/// is not a conflict, so this stays quiet across reconciles.
fn conflicting_fwmark_rule(rules: &str, mark: &str, table: &str) -> Option<String> {
    for line in rules.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(i) = toks.iter().position(|t| *t == "fwmark") else {
            continue;
        };
        // tolerate a mask suffix, e.g. `fwmark 0x1111/0xffffffff`.
        let rule_mark = toks
            .get(i + 1)
            .copied()
            .map(|t| t.split('/').next().unwrap_or(t));
        if rule_mark != Some(mark) {
            continue;
        }
        let looked_up = toks
            .iter()
            .position(|t| *t == "lookup")
            .and_then(|j| toks.get(j + 1))
            .copied();
        if looked_up != Some(table) {
            return Some(line.trim().to_owned());
        }
    }
    None
}

/// Apply the commands via `ip`.
///
/// # Errors
/// Fails if `ip` can't be spawned or a non-`ignore_fail` command errors.
pub fn apply(cmds: &[IpCmd]) -> Result<()> {
    for c in cmds {
        let out = Command::new("ip").args(&c.args).output().with_context(|| {
            format!(
                "spawning `ip {}` (is iproute2 installed?)",
                c.args.join(" ")
            )
        })?;
        if !out.status.success() && !c.ignore_fail {
            bail!(
                "`ip {}` failed: {}",
                c.args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::v1alpha1::{Egress as CfgEgress, Gateway};
    use crate::plan::{GatewayPlan, Plan};
    use std::collections::BTreeSet;

    fn gw() -> Gateway {
        Gateway {
            name: "vpn".to_owned(),
            egress: CfgEgress::default(),
            snat: Some(false),
            mark: Some("0x4".to_owned()),
            table: Some(200),
            default: false,
            local_subnets: vec![],
            members: vec![],
        }
    }

    fn flat(cmds: &[IpCmd]) -> Vec<String> {
        cmds.iter().map(|c| c.args.join(" ")).collect()
    }

    #[test]
    fn interface_egress_routes_via_dev_with_blackhole_fallback() {
        let g = gw();
        let plan = Plan {
            gateways: vec![GatewayPlan {
                gateway: g,
                egress: Egress::Interface("wg0".to_owned()),
                members: BTreeSet::new(),
                member_names: BTreeSet::new(),
            }],
            unresolved: vec![],
            conflicts: vec![],
            discovery_errors: vec![],
        };
        let cmds = build(&plan).unwrap();
        let f = flat(&cmds);
        assert!(
            f.iter()
                .any(|c| c == "rule add fwmark 0x4 table 200 priority 100"),
            "{f:?}"
        );
        assert!(
            f.iter()
                .any(|c| c == "route replace default dev wg0 table 200 proto 194 metric 1"),
            "{f:?}"
        );
        assert!(
            f.iter()
                .any(|c| c == "route replace blackhole default table 200 proto 194 metric 9999"),
            "{f:?}"
        );
    }

    #[test]
    fn unavailable_egress_has_only_the_blackhole_default() {
        let g = gw();
        let plan = Plan {
            gateways: vec![GatewayPlan {
                gateway: g,
                egress: Egress::Unavailable("down".to_owned()),
                members: BTreeSet::new(),
                member_names: BTreeSet::new(),
            }],
            unresolved: vec![],
            conflicts: vec![],
            discovery_errors: vec![],
        };
        let cmds = build(&plan).unwrap();
        let f = flat(&cmds);
        assert!(
            f.iter()
                .any(|c| c == "route replace blackhole default table 200 proto 194 metric 9999"),
            "{f:?}"
        );
        assert!(
            f.iter()
                .any(|c| c == "route del default table 200 proto 194 metric 1"),
            "stale live default removed: {f:?}"
        );
        assert!(
            !f.iter().any(|c| c.starts_with("route replace default")),
            "no live default: {f:?}"
        );
    }

    #[test]
    fn teardown_removes_rule_and_flushes_table_idempotently() {
        let g = gw();
        let gws = Gateways(vec![g]);
        let cmds = teardown(&gws).unwrap();
        let f = flat(&cmds);
        assert!(
            f.iter().any(|c| c == "rule del fwmark 0x4 table 200"),
            "{f:?}"
        );
        assert!(
            f.iter().any(|c| c == "route flush table 200 proto 194"),
            "{f:?}"
        );
        assert!(
            cmds.iter().all(|c| c.ignore_fail),
            "teardown must tolerate absent state: {f:?}"
        );
    }

    #[test]
    fn foreign_route_flags_only_non_degc_routes() {
        // degc's own routes carry `proto 194` → not foreign.
        let ours =
            "default dev wg0 table 200 proto 194 metric 1\nblackhole default proto 194 metric 9999";
        assert!(
            foreign_route(ours).is_none(),
            "our own routes must not be flagged"
        );
        assert!(
            foreign_route("").is_none(),
            "empty/absent table = no occupant"
        );
        assert!(foreign_route("default via 10.0.0.1 dev eth0 proto static metric 100").is_some());
    }

    #[test]
    fn conflicting_fwmark_rule_flags_other_table_only() {
        let ours = "0:\tfrom all lookup local\n200:\tfrom all fwmark 0x4 lookup 200";
        assert!(
            conflicting_fwmark_rule(ours, "0x4", "200").is_none(),
            "our own rule is not a conflict"
        );
        // same mark, different table → conflict
        let foreign = "100:\tfrom all fwmark 0x4 lookup 999";
        assert!(conflicting_fwmark_rule(foreign, "0x4", "200").is_some());
        // a different mark (e.g. nm-wg) → ignored
        let other = "31729:\tnot from all fwmark 0xcc4d lookup 52301";
        assert!(conflicting_fwmark_rule(other, "0x4", "200").is_none());
        // a masked fwmark that still matches our mark → still a conflict
        let masked = "100:\tfrom all fwmark 0x4/0xffffffff lookup 999";
        assert!(
            conflicting_fwmark_rule(masked, "0x4", "200").is_some(),
            "mask suffix must still match"
        );
    }

    #[test]
    fn blackhole_floor_precedes_the_diversion_rule_and_no_flush_window() {
        let g = gw();
        let plan = Plan {
            gateways: vec![GatewayPlan {
                gateway: g,
                egress: Egress::Interface("wg0".to_owned()),
                members: BTreeSet::new(),
                member_names: BTreeSet::new(),
            }],
            unresolved: vec![],
            conflicts: vec![],
            discovery_errors: vec![],
        };
        let f = flat(&build(&plan).unwrap());
        let blackhole = f
            .iter()
            .position(|c| c.starts_with("route replace blackhole"))
            .expect("blackhole");
        let rule = f
            .iter()
            .position(|c| c.starts_with("rule add fwmark"))
            .expect("rule");
        assert!(
            blackhole < rule,
            "fail-closed floor must exist before diverting traffic: {f:?}"
        );
        assert!(
            !f.iter().any(|c| c.starts_with("route flush")),
            "no flush -> no empty-table leak window: {f:?}"
        );
    }

    #[test]
    fn high_table_id_keeps_fixed_rule_priority() {
        let mut g = gw();
        g.table = Some(60000); // above main's 32766
        let plan = Plan {
            gateways: vec![GatewayPlan {
                gateway: g,
                egress: Egress::Interface("wg0".to_owned()),
                members: BTreeSet::new(),
                member_names: BTreeSet::new(),
            }],
            unresolved: vec![],
            conflicts: vec![],
            discovery_errors: vec![],
        };
        let f = flat(&build(&plan).unwrap());
        assert!(
            f.iter()
                .any(|c| c == "rule add fwmark 0x4 table 60000 priority 100"),
            "priority must stay fixed (not the table id, which would fall after main): {f:?}"
        );
    }
}

// SPDX-License-Identifier: MIT
//! Turns a [`Plan`] into the desired host state and applies it. Two backends
//! consume the same [`Desired`], so `--dry-run` shows exactly what `run` would
//! program:
//! - [`DryRunEnforcer`] logs the state and touches nothing.
//! - [`SystemEnforcer`] programs it via `nft -f` (atomic table replace) and `ip`
//!   (policy routing).

pub mod nft;
pub mod route;

use std::fmt;

use anyhow::Result;
use tracing::{info, warn};

use crate::api::v1alpha1::Gateways;
use crate::plan::Plan;
use route::IpCmd;

/// The compiled host state degc wants: the `inet degc` nft script plus the
/// `ip` routing commands. Rebuilt from scratch every reconcile.
#[derive(Debug, Clone)]
pub struct Desired {
    /// Config problems worth surfacing (a container opted into an unknown gateway).
    pub warnings: Vec<String>,
    /// The full `nft -f` script for the `inet degc` table.
    pub nft: String,
    /// The ordered `ip` routing commands.
    pub ip: Vec<IpCmd>,
    /// `(mark, table)` per gateway — the routing identities to preflight for
    /// collisions before programming (the nft table is namespaced by name).
    pub guards: Vec<(String, u32)>,
}

/// Compile the plan into the desired host state.
///
/// # Errors
/// Fails if a gateway's mark can't be parsed.
pub fn compile(plan: &Plan) -> Result<Desired> {
    // Fail closed if two gateways (config + label-discovered) resolve to the same
    // mark/table — that would misroute one gateway's members out another's egress.
    crate::api::v1alpha1::check_unique_routing(plan.gateways.iter().map(|gp| &gp.gateway))?;
    let warnings = plan
        .unresolved
        .iter()
        .map(|(c, via)| {
            format!("container {c:?} opted into gateway {via:?} — no such gateway (not routed)")
        })
        .collect();
    let mut guards = Vec::with_capacity(plan.gateways.len());
    for gp in &plan.gateways {
        guards.push((
            format!("0x{:x}", gp.gateway.mark_value()?),
            gp.gateway.table_id(),
        ));
    }
    Ok(Desired {
        warnings,
        nft: nft::build_script(plan)?,
        ip: route::build(plan)?,
        guards,
    })
}

/// Tear down all of degc's host state: the `inet degc` table plus every
/// configured gateway's policy routing. Backs `degc down` — the daemon
/// deliberately leaves the ruleset in place on stop (fail-closed), so removing
/// it is an explicit action.
///
/// # Errors
/// Fails if `nft`/`ip` can't be run or a gateway's mark can't be parsed.
pub fn down(gateways: &Gateways) -> Result<()> {
    nft::apply(nft::TEARDOWN_SCRIPT)?;
    route::apply(&route::teardown(gateways)?)?;
    info!("degc down — removed the inet degc table and policy routing");
    Ok(())
}

impl fmt::Display for Desired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "# degc desired host state")?;
        for w in &self.warnings {
            writeln!(f, "# WARNING: {w}")?;
        }
        writeln!(f, "# --- nftables (nft -f -) ---")?;
        write!(f, "{}", self.nft)?;
        writeln!(f, "# --- routing (ip) ---")?;
        for c in &self.ip {
            let note = if c.ignore_fail {
                "    # ok if absent"
            } else {
                ""
            };
            writeln!(f, "ip {}{note}", c.args.join(" "))?;
        }
        Ok(())
    }
}

/// Applies a [`Desired`] to the host — or, dry-run, just logs it.
pub trait Enforcer {
    /// Apply the desired state.
    ///
    /// # Errors
    /// Fails if programming the host fails (dry-run never fails).
    fn apply(&mut self, desired: &Desired) -> Result<()>;

    /// A short backend label for logs.
    fn label(&self) -> &'static str;
}

/// Logs the desired state and programs nothing.
pub struct DryRunEnforcer;

impl Enforcer for DryRunEnforcer {
    fn apply(&mut self, desired: &Desired) -> Result<()> {
        info!("dry-run — would apply:\n{desired}");
        Ok(())
    }

    fn label(&self) -> &'static str {
        "dry-run"
    }
}

/// Programs the host via `nft` (atomic table replace) and `ip` (routing).
pub struct SystemEnforcer;

impl Enforcer for SystemEnforcer {
    fn apply(&mut self, desired: &Desired) -> Result<()> {
        for w in &desired.warnings {
            warn!("{w}");
        }
        // fail-closed: refuse to program if a table/mark collides with a foreigner.
        route::preflight(&desired.guards)?;
        nft::apply(&desired.nft)?;
        route::apply(&desired.ip)?;
        Ok(())
    }

    fn label(&self) -> &'static str {
        "system (nft + ip)"
    }
}

/// Select the enforcement backend for the run mode.
#[must_use]
pub fn select(dry_run: bool) -> Box<dyn Enforcer> {
    if dry_run {
        Box::new(DryRunEnforcer)
    } else {
        Box::new(SystemEnforcer)
    }
}

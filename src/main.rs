// SPDX-License-Identifier: MIT
//! degc — label-driven VPN egress policy-routing for Docker.
//!
//! See `docs/architecture.md`. It reads the gateways config + container labels,
//! compiles the desired host state (nftables `inet degc` + `ip` policy routing)
//! and either logs it (`--dry-run`) or programs it via `nft -f` (atomic) and
//! `ip`. Enforcement needs CAP_NET_ADMIN plus `nft` + `ip` in the image.

mod api;
mod config;
mod docker;
mod enforce;
mod obs;
mod plan;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::api::v1alpha1::{self, Gateways, parse_gateways};
use crate::config::Config;
use crate::docker::Source;
use crate::enforce::Enforcer;
use crate::obs::{Metrics, ReconcileStats, Trigger};

/// degc command-line interface.
#[derive(Parser)]
#[command(
    name = "degc",
    version,
    about = "Label-driven VPN egress policy-routing for Docker"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the reconcile daemon until terminated. Without `--dry-run` it
    /// programs the host (needs CAP_NET_ADMIN + `nft`/`ip`).
    Run {
        /// Log the plan on each reconcile instead of programming the host.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove degc's host state (the `inet degc` table + policy routing).
    /// The daemon leaves rules in place on stop (fail-closed); this removes them.
    Down,
    /// Show governed containers and the resolved host-state plan, then exit.
    Status,
    /// Emit the gateways-config JSON Schema (as YAML).
    Schema,
    /// Validate a gateways config file offline (structure, marks, CIDRs).
    Validate {
        /// Path to the gateways file (default: `$DEGC_GATEWAYS_PATH`).
        path: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { dry_run } => run(dry_run).await,
        Command::Status => status().await,
        Command::Schema => {
            println!("{}", schema_yaml()?);
            Ok(())
        }
        Command::Validate { path } => validate(path),
        Command::Down => down(),
    }
}

/// An on-restart callback for the Docker event watcher: counts the self-heal in
/// metrics and logs it. Fires on a real stream re-subscription.
fn watch_logger(metrics: &Arc<Metrics>) -> impl Fn() + Send + 'static {
    let metrics = Arc::clone(metrics);
    move || {
        metrics.watch_restarted();
        warn!("docker event watcher resubscribed");
    }
}

/// Run the reconcile daemon until terminated (SIGINT/SIGTERM).
async fn run(dry_run: bool) -> Result<()> {
    init_tracing();
    let config = Config::from_env();
    let mut enforcer = enforce::select(dry_run);
    info!(
        api_version = v1alpha1::VERSION,
        backend = enforcer.label(),
        ?config,
        "starting degc"
    );

    let metrics = Arc::new(Metrics::default());
    if let Some(addr) = config.metrics_addr {
        obs::serve(addr, Arc::clone(&metrics));
    }

    let gateways = load_gateways(&config)?;
    info!(gateways = gateways.0.len(), "loaded gateways");

    let source = Source::connect()?;
    // Last applied state summary, so a reconcile that changes nothing logs at
    // DEBUG instead of repeating an INFO line every resync tick.
    let mut last_fp: Option<String> = None;
    // Fail-closed: the first reconcile must succeed before we settle into the loop.
    reconcile(
        &source,
        &config,
        &gateways,
        enforcer.as_mut(),
        &metrics,
        Trigger::Startup,
        &mut last_fp,
    )
    .await
    .context("initial reconcile")?;

    let mut events = source.watch(watch_logger(&metrics));
    let mut ticker = tokio::time::interval(config.resync_interval);
    ticker.tick().await; // the first tick fires immediately; skip it

    let shutdown = shutdown();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!("shutting down — leaving the ruleset in place (fail-closed); run `degc down` to remove");
                return Ok(());
            }
            _ = ticker.tick() => {
                if let Err(err) = reconcile(&source, &config, &gateways, enforcer.as_mut(), &metrics, Trigger::Resync, &mut last_fp).await {
                    warn!("reconcile failed: {err:?}");
                }
            }
            signal = events.recv() => {
                if signal.is_none() {
                    warn!("docker event watcher stopped; re-establishing");
                    events = source.watch(watch_logger(&metrics));
                    continue;
                }
                debounce(&mut events, config.debounce).await;
                if let Err(err) = reconcile(&source, &config, &gateways, enforcer.as_mut(), &metrics, Trigger::Event, &mut last_fp).await {
                    warn!("reconcile failed: {err:?}");
                }
            }
        }
    }
}

/// One reconcile: snapshot containers, compile + apply, log a state summary,
/// and record metrics.
async fn reconcile(
    source: &Source,
    config: &Config,
    gateways: &Gateways,
    enforcer: &mut dyn Enforcer,
    metrics: &Metrics,
    trigger: Trigger,
    last_fp: &mut Option<String>,
) -> Result<()> {
    let start = Instant::now();
    let outcome = reconcile_apply(source, config, gateways, enforcer, trigger, last_fp).await;
    metrics.record(trigger, start.elapsed(), outcome.as_ref().ok());
    outcome.map(|_| ())
}

/// Snapshot → compile → apply; returns the reconcile summary for metrics. Logs
/// the applied state at INFO when it changed since the last apply (so the
/// periodic resync stays quiet unless something actually moved), else DEBUG.
async fn reconcile_apply(
    source: &Source,
    config: &Config,
    gateways: &Gateways,
    enforcer: &mut dyn Enforcer,
    trigger: Trigger,
    last_fp: &mut Option<String>,
) -> Result<ReconcileStats> {
    let targets = source.list_targets().await?;
    let plan = plan::compile(&targets, &config.label_prefix, gateways);
    let desired = enforce::compile(&plan)?;
    enforcer.apply(&desired)?;

    let summary = plan_summary(&plan);
    if last_fp.as_deref() == Some(summary.as_str()) {
        debug!(
            trigger = trigger.as_str(),
            "reconciled, no change: {summary}"
        );
    } else {
        info!(trigger = trigger.as_str(), "{summary}");
        for (container, via) in &plan.unresolved {
            warn!("container {container:?} wants gateway {via:?} — no such gateway (not routed)");
        }
        for (container, gws) in &plan.conflicts {
            warn!(
                "container {container:?} matches multiple gateway selectors {gws:?} — not routed"
            );
        }
        for err in &plan.discovery_errors {
            warn!("{err}");
        }
        *last_fp = Some(summary);
    }

    let members = plan.gateways.iter().map(|g| g.members.len()).sum();
    let gateways = plan
        .gateways
        .iter()
        .map(|g| {
            (
                g.gateway.name.clone(),
                !matches!(g.egress, plan::Egress::Unavailable(_)),
            )
        })
        .collect();
    Ok(ReconcileStats { members, gateways })
}

/// A one-line, human-readable summary of the resolved plan — the INFO signal
/// for "what state did this reconcile apply", and the change fingerprint.
fn plan_summary(plan: &plan::Plan) -> String {
    let mut parts: Vec<String> = plan
        .gateways
        .iter()
        .map(|g| {
            let egress = match &g.egress {
                plan::Egress::Interface(i) => format!("dev {i}"),
                plan::Egress::NextHop(ip) => format!("via {ip}"),
                plan::Egress::Unavailable(_) => "DOWN".to_owned(),
            };
            let names = g.member_names.iter().cloned().collect::<Vec<_>>().join(",");
            format!(
                "{}={egress} members={}[{names}]",
                g.gateway.name,
                g.members.len()
            )
        })
        .collect();
    if !plan.unresolved.is_empty() {
        parts.push(format!("unresolved={}", plan.unresolved.len()));
    }
    if !plan.conflicts.is_empty() {
        parts.push(format!("conflicts={}", plan.conflicts.len()));
    }
    if !plan.discovery_errors.is_empty() {
        parts.push(format!("gatewayErrors={}", plan.discovery_errors.len()));
    }
    if parts.is_empty() {
        "no gateways".to_owned()
    } else {
        parts.join("  ")
    }
}

/// Show the resolved plan + desired host state once, without applying it.
async fn status() -> Result<()> {
    init_tracing();
    let config = Config::from_env();
    let gateways = load_gateways(&config)?;
    let source = Source::connect()?;
    let targets = source.list_targets().await?;
    let plan = plan::compile(&targets, &config.label_prefix, &gateways);
    for gp in &plan.gateways {
        let gw = &gp.gateway;
        let egress = match &gp.egress {
            plan::Egress::Interface(i) => format!("interface {i}"),
            plan::Egress::NextHop(ip) => format!("via {ip}"),
            plan::Egress::Unavailable(why) => format!("UNAVAILABLE ({why})"),
        };
        let mark = gw
            .mark_value()
            .map_or_else(|_| "?".to_owned(), |m| format!("0x{m:x}"));
        println!(
            "# gateway {name:<12} egress={egress}  mark={mark} table={table}  members={members}",
            name = gw.name,
            table = gw.table_id(),
            members = gp.members.len(),
        );
        if !gp.member_names.is_empty() {
            let names = gp
                .member_names
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            println!("#   members: {names}");
        }
    }
    for (container, via) in &plan.unresolved {
        println!("# WARNING: container {container:?} wants gateway {via:?} — no such gateway");
    }
    for (container, gws) in &plan.conflicts {
        println!(
            "# WARNING: container {container:?} matches multiple gateway selectors {gws:?} — not routed (set degc.via)"
        );
    }
    for err in &plan.discovery_errors {
        println!("# WARNING: {err}");
    }
    print!("{}", enforce::compile(&plan)?);
    Ok(())
}

/// Remove degc's host state (`inet degc` + policy routing). The daemon
/// leaves rules in place on stop (fail-closed); this is the explicit removal.
/// Reads the same gateways config to know which marks/tables to clear.
fn down() -> Result<()> {
    init_tracing();
    let config = Config::from_env();
    let gateways = load_gateways(&config)?;
    enforce::down(&gateways)
}

/// Validate a gateways config file offline.
fn validate(path: Option<PathBuf>) -> Result<()> {
    init_tracing();
    let path = path.unwrap_or_else(|| Config::from_env().gateways_path);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading gateways from {}", path.display()))?;
    let gws = parse_gateways(&text)?;
    println!("ok: {} gateway(s) valid", gws.0.len());
    Ok(())
}

/// Read + parse the gateways config. A MISSING file is fine — gateways can be
/// discovered from `<prefix>.gateway` labels instead — so it yields an empty
/// set; a present-but-malformed file still errors.
fn load_gateways(config: &Config) -> Result<Gateways> {
    match std::fs::read_to_string(&config.gateways_path) {
        Ok(text) => parse_gateways(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Gateways::default()),
        Err(e) => Err(e)
            .with_context(|| format!("reading gateways from {}", config.gateways_path.display())),
    }
}

/// The gateways-config JSON Schema, rendered as YAML.
fn schema_yaml() -> Result<String> {
    let schema = schemars::schema_for!(Vec<v1alpha1::Gateway>);
    serde_yaml_ng::to_string(&schema).context("serializing schema")
}

/// Wait until Docker events have been quiet for `delay`, draining any that
/// arrive within the window.
async fn debounce(events: &mut mpsc::Receiver<()>, delay: Duration) {
    while let Ok(signal) = tokio::time::timeout(delay, events.recv()).await {
        if signal.is_none() {
            break; // channel closed
        }
    }
}

/// Resolve when the process is asked to terminate (SIGINT or SIGTERM).
async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            () = ctrl_c => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

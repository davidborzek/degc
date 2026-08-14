// SPDX-License-Identifier: MIT
//! Observability: Prometheus metrics + health endpoints, served with axum. Opt
//! in with `DEGC_METRICS_ADDR` (e.g. `0.0.0.0:9101`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use tracing::{error, info};

/// What triggered a reconcile (a `degc_reconciles_total` label value).
#[derive(Clone, Copy)]
pub enum Trigger {
    Startup,
    Event,
    Resync,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Event => "event",
            Self::Resync => "resync",
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReconcileLabels {
    trigger: &'static str,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct GatewayLabels {
    gateway: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildLabels {
    version: &'static str,
}

/// A successful reconcile's summary, recorded into the metrics.
pub struct ReconcileStats {
    /// Total opted-in member containers routed.
    pub members: usize,
    /// `(gateway name, egress available)` — `false` means fail-closed (blackhole).
    pub gateways: Vec<(String, bool)>,
}

/// Reconcile metrics, updated by the reconcile loop and exposed at `/metrics`.
pub struct Metrics {
    registry: Registry,
    reconciles: Family<ReconcileLabels, Counter>,
    duration: Histogram,
    last_success: Gauge,
    members: Gauge,
    gateways: Gauge,
    gateway_available: Family<GatewayLabels, Gauge>,
    ready: Gauge,
    watch_restarts: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        let reconciles = Family::<ReconcileLabels, Counter>::default();
        let duration = Histogram::new(
            [
                0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0,
            ]
            .into_iter(),
        );
        let last_success = Gauge::default();
        let members = Gauge::default();
        let gateways = Gauge::default();
        let gateway_available = Family::<GatewayLabels, Gauge>::default();
        let ready = Gauge::default();
        let watch_restarts = Counter::default();

        // Build info: a constant `1` carrying the version as a label.
        let build = Family::<BuildLabels, Gauge>::default();
        build
            .get_or_create(&BuildLabels {
                version: env!("CARGO_PKG_VERSION"),
            })
            .set(1);

        let mut registry = Registry::default();
        registry.register("degc_build_info", "Build information", build);
        registry.register(
            "degc_reconciles",
            "Reconciles attempted",
            reconciles.clone(),
        );
        registry.register(
            "degc_reconcile_duration_seconds",
            "Reconcile duration",
            duration.clone(),
        );
        registry.register(
            "degc_last_reconcile_success_timestamp_seconds",
            "Unix time of the last successful reconcile",
            last_success.clone(),
        );
        registry.register(
            "degc_members",
            "Opted-in member containers routed in the last reconcile",
            members.clone(),
        );
        registry.register(
            "degc_gateways",
            "Gateways in the last reconcile (config + discovered)",
            gateways.clone(),
        );
        registry.register(
            "degc_gateway_available",
            "Whether a gateway's egress resolved (1) or is fail-closed / blackholed (0)",
            gateway_available.clone(),
        );
        registry.register(
            "degc_ready",
            "Whether at least one reconcile has succeeded",
            ready.clone(),
        );
        registry.register(
            "degc_watch_restarts",
            "Docker event watcher re-establishments",
            watch_restarts.clone(),
        );

        Self {
            registry,
            reconciles,
            duration,
            last_success,
            members,
            gateways,
            gateway_available,
            ready,
            watch_restarts,
        }
    }
}

impl Metrics {
    /// Record a completed reconcile: `Some(stats)` on success, `None` on failure.
    pub fn record(&self, trigger: Trigger, elapsed: Duration, outcome: Option<&ReconcileStats>) {
        let result = if outcome.is_some() {
            "success"
        } else {
            "error"
        };
        self.reconciles
            .get_or_create(&ReconcileLabels {
                trigger: trigger.as_str(),
                result,
            })
            .inc();
        self.duration.observe(elapsed.as_secs_f64());
        if let Some(stats) = outcome {
            self.members.set(clamp(stats.members));
            self.gateways.set(clamp(stats.gateways.len()));
            // Drop series for gateways that no longer exist (bounds cardinality,
            // avoids a removed gateway reporting a stale availability forever).
            self.gateway_available.clear();
            for (name, up) in &stats.gateways {
                self.gateway_available
                    .get_or_create(&GatewayLabels {
                        gateway: name.clone(),
                    })
                    .set(i64::from(*up));
            }
            self.last_success.set(clamp_u64(unix_now()));
            self.ready.set(1);
        }
    }

    /// Count a re-established Docker event watcher (self-heal).
    pub fn watch_restarted(&self) {
        self.watch_restarts.inc();
    }

    /// Whether at least one reconcile has succeeded.
    fn ready(&self) -> bool {
        self.ready.get() == 1
    }

    /// Render the OpenMetrics/Prometheus text exposition format.
    fn render(&self) -> String {
        let mut buf = String::new();
        encode(&mut buf, &self.registry).expect("encoding metrics into a String cannot fail");
        buf
    }
}

fn clamp(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn clamp_u64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Spawn the metrics/health HTTP server on `addr`: `GET /metrics` (Prometheus),
/// `/healthz` (liveness) and `/readyz` (200 after the first successful
/// reconcile). Best-effort: a bind failure is logged, not fatal.
pub fn serve(addr: SocketAddr, metrics: Arc<Metrics>) {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(async || "ok\n"))
        .route("/readyz", get(readyz_handler))
        .with_state(metrics);
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(err) => {
                error!(%addr, %err, "metrics server: bind failed");
                return;
            }
        };
        info!(%addr, "metrics/health server listening");
        if let Err(err) = axum::serve(listener, app).await {
            error!(%err, "metrics server stopped");
        }
    });
}

async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        metrics.render(),
    )
}

async fn readyz_handler(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    if metrics.ready() {
        (axum::http::StatusCode::OK, "ok\n")
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_renders() {
        let m = Metrics::default();
        assert!(!m.ready());
        m.record(
            Trigger::Startup,
            Duration::from_millis(3),
            Some(&ReconcileStats {
                members: 2,
                gateways: vec![("vpn".to_owned(), true)],
            }),
        );
        assert!(m.ready());
        let out = m.render();
        assert!(out.contains("degc_reconciles_total"), "{out}");
        assert!(out.contains("degc_members"), "{out}");
        assert!(out.contains("degc_gateway_available"), "{out}");
        assert!(out.contains("gateway=\"vpn\""), "{out}");
        assert!(out.contains("degc_ready 1"), "{out}");
    }
}

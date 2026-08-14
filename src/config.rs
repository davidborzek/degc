// SPDX-License-Identifier: MIT
//! Runtime configuration, sourced from the environment.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

/// All runtime settings. Everything comes from the environment so degc is
/// trivially configurable in a compose file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Container label namespace, e.g. `degc` → `degc.enable` / `degc.via`.
    pub label_prefix: String,
    /// File or directory holding the gateway definitions (`gateways.yaml`).
    pub gateways_path: PathBuf,
    /// Periodic full reconcile interval (safety net against drift / missed events).
    pub resync_interval: Duration,
    /// Quiet period after a Docker event before reconciling (coalesces bursts).
    pub debounce: Duration,
    /// Optional `addr:port` for the Prometheus metrics + health server
    /// (`DEGC_METRICS_ADDR`); `None` disables it.
    pub metrics_addr: Option<SocketAddr>,
}

impl Config {
    /// Load configuration from the environment, applying defaults.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            label_prefix: env("DEGC_LABEL_PREFIX", "degc"),
            gateways_path: PathBuf::from(env("DEGC_GATEWAYS_PATH", "/etc/degc/gateways.yaml")),
            resync_interval: Duration::from_secs(env_u64("DEGC_RESYNC_INTERVAL", 30).max(1)),
            debounce: Duration::from_millis(env_u64("DEGC_DEBOUNCE_MS", 500)),
            metrics_addr: std::env::var("DEGC_METRICS_ADDR")
                .ok()
                .and_then(|s| s.parse().ok()),
        }
    }
}

fn env(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_owned())
}

fn env_u64(key: &str, fallback: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply() {
        // Not touching real env; just exercise the parse helpers' fallbacks.
        assert_eq!(env_u64("DEGC_DOES_NOT_EXIST", 7), 7);
        assert_eq!(env("DEGC_DOES_NOT_EXIST", "x"), "x");
    }
}

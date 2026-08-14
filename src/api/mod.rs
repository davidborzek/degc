// SPDX-License-Identifier: MIT
//! Public API: the gateway configuration model and the container-label
//! convention degc reads its desired state from.
//!
//! Versioned API with a maturity ladder (`v1alpha1` → `v1beta1` → `v1`); a new
//! version becomes a sibling module.

pub mod v1alpha1;

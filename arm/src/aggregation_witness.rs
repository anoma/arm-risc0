//! Witness types passed from the host to the aggregation guest.
//!
//! The aggregation guest receives a single [`AggregationWitness`] value and
//! uses it to verify every compliance and logic proof in a transaction.
//!
//! # Design
//!
//! Only data that is not already present in the compliance instance is included
//! here.  Specifically, each [`ActionWitness`] carries the typed
//! [`ComplianceInstance`] (from which the guest derives tags,
//! `resource_logic_ref` values, and the action-tree root in-circuit) together
//! with the per-resource [`AppData`] values — the only information that the
//! compliance instance does not contain.
//!
//! The guest reconstructs each [`LogicInstance`](crate::logic_instance::LogicInstance)
//! from context alone and calls `env::verify` with the result, so constraints
//! A/B/C are enforced structurally rather than via explicit assertions:
//!
//! | Constraint | Enforced by |
//! |---|---|
//! | A – tag matches nullifier/commitment | tag comes from the compliance instance |
//! | B – root matches action-tree root    | root recomputed in-circuit from compliance tags |
//! | C – VK matches `resource_logic_ref`  | `resource_logic_ref` used directly as the `env::verify` key |

use crate::{compliance::ComplianceInstance, logic_instance::AppData};
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

/// All witness data consumed by the aggregation guest in a single read.
#[derive(Serialize, Deserialize)]
pub struct AggregationWitness {
    /// Verification key of the compliance circuit.
    pub compliance_key: Digest,
    /// One witness per action, in the order they appear in the transaction.
    pub actions: Vec<ActionWitness>,
}

/// Aggregation witness for a single action.
///
/// The compliance instance carries the tags (`resource_nullifier` /
/// `resource_commitment`) and `resource_logic_ref` values that the guest uses
/// to reconstruct each `LogicInstance` in-circuit.  Only the `app_data` fields
/// — the only information not already present in the compliance instance — are
/// supplied separately.
#[derive(Serialize, Deserialize)]
pub struct ActionWitness {
    /// Typed compliance instance for this action.
    pub compliance_instance: ComplianceInstance,
    /// `app_data` for each consumed resource, in the same order as
    /// `compliance_instance.consumed_publics`.
    pub consumed_app_data: Vec<AppData>,
    /// `app_data` for each created resource, in the same order as
    /// `compliance_instance.created_publics`.
    pub created_app_data: Vec<AppData>,
}

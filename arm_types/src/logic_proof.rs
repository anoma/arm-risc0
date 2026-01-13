//! Logic proof structures and traits for proving and verifying logic statements.

use crate::logic_instance::AppData;
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

/// Inputs required to create a logic verifier.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct LogicVerifierInputs {
    /// The tag (either commitment or nullifier) for the logic instance.
    pub tag: Digest,
    /// The verifying key for the logic proof.
    pub verifying_key: Digest,
    /// The application data associated with the logic instance.
    pub app_data: AppData,
    /// The logic proof (optional, would be absent when aggregation is enabled).
    pub proof: Option<Vec<u8>>,
}

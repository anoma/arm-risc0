use crate::compliance::ComplianceInstance;
use serde::{Deserialize, Serialize};

/// A compliance unit consists of a compliance proof and its structured instance.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ComplianceUnit {
    /// The compliance proof bytes (None when aggregation is enabled).
    pub proof: Option<Vec<u8>>,
    /// The compliance instance (structured public inputs).
    pub instance: ComplianceInstance,
}

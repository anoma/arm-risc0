//! Compliance unit module containing the compliance proof and instance.

use crate::{compliance::ComplianceInstance, error::ArmError};
use k256::ProjectivePoint;
use serde::{Deserialize, Serialize};

/// A compliance unit consists of a compliance proof and its corresponding instance.
/// The vk is a constant in the compliance unit, so we don't place it here.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ComplianceUnit {
    /// The compliance proof (optional, would be absent when aggregation is enabled).
    pub proof: Option<Vec<u8>>,
    /// The compliance instance.
    pub instance: ComplianceInstance,
}

impl ComplianceUnit {
    /// Obtains the delta from the compliance instance.
    pub fn delta(&self) -> Result<ProjectivePoint, ArmError> {
        self.instance.delta_projective()
    }
}

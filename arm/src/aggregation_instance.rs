//! Compact aggregation instance committed by the batch aggregation guest.

use crate::{
    error::ArmError,
    logic_instance::AppData,
    utils::words_to_bytes,
};
use k256::{elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, ProjectivePoint};
use risc0_zkvm::Digest;
use serde::{Deserialize, Serialize};

/// The public output committed by the aggregation guest.
///
/// Contains all information needed by a verifier to check the aggregated
/// transaction without re-running the compliance↔logic cross-checks —
/// those are now enforced inside the guest circuit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AggregationInstance {
    /// VK of the compliance circuit — single for the whole transaction.
    pub compliance_key: Digest,
    /// Shared across all actions; equality enforced in-circuit.
    pub kind_table_commitment: Digest,
    /// One entry per compliance unit / action.
    pub actions: Vec<ActionAggregated>,
}

/// Per-action aggregated public data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActionAggregated {
    /// Consumed resources with merged app_data.
    pub consumed_publics: Vec<ConsumedResourceAggregated>,
    /// Created resources with merged app_data.
    pub created_publics: Vec<CreatedResourceAggregated>,
    /// Delta x coordinate ([u32; 8] avoids risc0 padding issues).
    pub delta_x: [u32; 8],
    /// Delta y coordinate ([u32; 8] avoids risc0 padding issues).
    pub delta_y: [u32; 8],
    /// Merkle root of the action tree; computed inside the aggregation circuit.
    pub action_tree_root: Digest,
}

/// Consumed resource public data merged with its logic circuit app_data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsumedResourceAggregated {
    /// The resource's nullifier.
    pub resource_nullifier: Digest,
    /// The logic circuit VK that was verified for this resource.
    pub resource_logic_ref: Digest,
    /// Merkle root of the commitment tree in which the resource is included.
    pub commitment_tree_root: Digest,
    /// Application data emitted by the logic circuit.
    pub app_data: AppData,
}

/// Created resource public data merged with its logic circuit app_data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CreatedResourceAggregated {
    /// The resource's commitment.
    pub resource_commitment: Digest,
    /// The logic circuit VK that was verified for this resource.
    pub resource_logic_ref: Digest,
    /// Application data emitted by the logic circuit.
    pub app_data: AppData,
}

impl ActionAggregated {
    /// Decodes the stored delta_x/delta_y coordinates into a projective point.
    pub fn delta_projective(&self) -> Result<ProjectivePoint, ArmError> {
        let encoded = EncodedPoint::from_affine_coordinates(
            words_to_bytes(&self.delta_x).into(),
            words_to_bytes(&self.delta_y).into(),
            false,
        );
        ProjectivePoint::from_encoded_point(&encoded)
            .into_option()
            .ok_or(ArmError::InvalidDelta)
    }
}

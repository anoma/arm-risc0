//! Compact aggregation instance committed by the batch aggregation guest.

use crate::logic_instance::AppData;
use risc0_zkp::core::digest::Digest;
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

impl AggregationInstance {
    /// The delta message of the aggregated transaction: the concatenation of
    /// each action's action-tree root (32 bytes each). Verifier engines hash
    /// this (keccak) before signature recovery.
    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(self.actions.len() * 32);
        for a in &self.actions {
            msg.extend_from_slice(a.action_tree_root.as_bytes());
        }
        msg
    }

    /// Checks that no nullifier appears twice across the instance's actions.
    pub fn nf_duplication_check(&self) -> Result<(), crate::error::ArmError> {
        let mut seen_nullifiers = std::collections::HashSet::new();
        for action in &self.actions {
            for consumed in &action.consumed_publics {
                if !seen_nullifiers.insert(consumed.resource_nullifier) {
                    return Err(crate::error::ArmError::NullifierDuplication);
                }
            }
        }
        Ok(())
    }
}

//! Compact aggregation instance committed by the batch aggregation guest.

use crate::logic_instance::AppData;
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

/// The public output committed by the aggregation guest.
///
/// Contains all information needed by a verifier to check the aggregated
/// transaction without re-running the compliance↔logic cross-checks —
/// those are now enforced inside the guest circuit.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AggregationInstance {
    /// VK of the compliance circuit — single for the whole transaction.
    pub compliance_key: Digest,
    /// Shared across all actions; equality enforced in-circuit.
    pub kind_tree_root: Digest,
    /// One entry per compliance unit / action.
    pub actions: Vec<ActionAggregated>,
}

/// The part of the aggregation instance for one action.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActionAggregated {
    /// The part of the aggregation instance for each consumed and created resource, in the order
    /// in which the verifier processes them.
    pub resource_instances: Vec<AggregationResourceInstance>,
    /// Delta x coordinate ([u32; 8] avoids risc0 padding issues).
    pub delta_x: [u32; 8],
    /// Delta y coordinate ([u32; 8] avoids risc0 padding issues).
    pub delta_y: [u32; 8],
    /// Merkle root of the action tree; computed inside the aggregation circuit.
    pub action_tree_root: Digest,
}

/// The part of the aggregation instance for one resource: its compliance data and the app data
/// of its logic proof.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum AggregationResourceInstance {
    /// A consumed resource, identified by its nullifier.
    Consumed {
        /// The nullifier (tag) of the consumed resource.
        nullifier: Digest,
        /// The logic circuit VK that was verified for this resource.
        logic_ref: Digest,
        /// Merkle root of the commitment tree in which this resource is included.
        commitment_tree_root: Digest,
        /// Application data emitted by the logic circuit.
        app_data: AppData,
    },
    /// A created resource, identified by its commitment.
    Created {
        /// The commitment (tag) of the created resource.
        commitment: Digest,
        /// The logic circuit VK that was verified for this resource.
        logic_ref: Digest,
        /// Application data emitted by the logic circuit.
        app_data: AppData,
    },
}

impl AggregationResourceInstance {
    /// The tag of the resource: the nullifier if consumed, the commitment if created.
    pub fn tag(&self) -> Digest {
        match self {
            AggregationResourceInstance::Consumed { nullifier, .. } => *nullifier,
            AggregationResourceInstance::Created { commitment, .. } => *commitment,
        }
    }

    /// The logic circuit VK of the resource.
    pub fn logic_ref(&self) -> Digest {
        match self {
            AggregationResourceInstance::Consumed { logic_ref, .. } => *logic_ref,
            AggregationResourceInstance::Created { logic_ref, .. } => *logic_ref,
        }
    }

    /// Whether the resource is consumed.
    pub fn is_consumed(&self) -> bool {
        matches!(self, AggregationResourceInstance::Consumed { .. })
    }

    /// The commitment tree root for a consumed resource, or `None` for a created resource.
    pub fn commitment_tree_root(&self) -> Option<Digest> {
        match self {
            AggregationResourceInstance::Consumed {
                commitment_tree_root,
                ..
            } => Some(*commitment_tree_root),
            AggregationResourceInstance::Created { .. } => None,
        }
    }

    /// The application data emitted by the logic circuit.
    pub fn app_data(&self) -> &AppData {
        match self {
            AggregationResourceInstance::Consumed { app_data, .. } => app_data,
            AggregationResourceInstance::Created { app_data, .. } => app_data,
        }
    }
}

impl AggregationInstance {
    /// Serializes the instance exactly as risc0-serde does when the batch
    /// aggregation guest commits it — the byte sequence whose sha256 digest
    /// is the Groth16 journal digest an on-chain verifier must re-derive.
    ///
    /// Hand-rolled so no zkVM dependency is needed: risc0-serde encodes a
    /// value as a `u32` word stream (`Digest` as its 8 words, `Vec` as a
    /// length word plus elements, fixed arrays with no length prefix, enums
    /// as a variant-index word followed by the variant's fields), emitted as
    /// little-endian bytes. Equivalence with `risc0_zkvm::serde::to_vec` is
    /// pinned by the `journal_format` tests in `anoma-rm-risc0`.
    pub fn to_journal(&self) -> Vec<u8> {
        let mut words: Vec<u32> = Vec::new();
        words.extend_from_slice(self.compliance_key.as_words());
        words.extend_from_slice(self.kind_tree_root.as_words());
        words.push(self.actions.len() as u32);
        for action in &self.actions {
            words.push(action.resource_instances.len() as u32);
            for resource in &action.resource_instances {
                match resource {
                    AggregationResourceInstance::Consumed {
                        nullifier,
                        logic_ref,
                        commitment_tree_root,
                        app_data,
                    } => {
                        words.push(0u32); // variant index for Consumed
                        words.extend_from_slice(nullifier.as_words());
                        words.extend_from_slice(logic_ref.as_words());
                        words.extend_from_slice(commitment_tree_root.as_words());
                        app_data.encode_journal(&mut words);
                    }
                    AggregationResourceInstance::Created {
                        commitment,
                        logic_ref,
                        app_data,
                    } => {
                        words.push(1u32); // variant index for Created
                        words.extend_from_slice(commitment.as_words());
                        words.extend_from_slice(logic_ref.as_words());
                        app_data.encode_journal(&mut words);
                    }
                }
            }
            words.extend_from_slice(&action.delta_x);
            words.extend_from_slice(&action.delta_y);
            words.extend_from_slice(action.action_tree_root.as_words());
        }
        crate::utils::words_to_bytes(&words).to_vec()
    }

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
            for consumed in action.resource_instances.iter().filter(|r| r.is_consumed()) {
                if !seen_nullifiers.insert(consumed.tag()) {
                    return Err(crate::error::ArmError::NullifierDuplication);
                }
            }
        }
        Ok(())
    }
}

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
    pub resources: Vec<ResourceAggregated>,
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
pub struct ResourceAggregated {
    /// `1` for a consumed resource, `0` for a created one. A word, as every
    /// field of the instance, so that the Borsh encoding is the journal.
    pub consumed: u32,
    /// The resource's tag: its nullifier if consumed, its commitment if created.
    pub tag: Digest,
    /// The logic circuit VK that was verified for this resource.
    pub logic_ref: Digest,
    /// Merkle root of the commitment tree in which a consumed resource is
    /// included; the zero digest for a created resource.
    pub commitment_tree_root: Digest,
    /// Application data emitted by the logic circuit.
    pub app_data: AppData,
}

impl ResourceAggregated {
    /// Whether the resource is consumed.
    pub fn is_consumed(&self) -> bool {
        self.consumed != 0
    }
}

impl AggregationInstance {
    /// Serializes the instance exactly as risc0-serde does when the batch
    /// aggregation guest commits it — the byte sequence whose sha256 digest
    /// is the Groth16 journal digest an on-chain verifier must re-derive.
    ///
    /// Hand-rolled so no zkVM dependency is needed: risc0-serde encodes a
    /// value as a `u32` word stream (structs as their fields in order,
    /// `Digest` as its 8 words, `Vec` as a length word plus elements,
    /// fixed arrays with no length prefix), emitted as little-endian bytes.
    /// Equivalence with `risc0_zkvm::serde::to_vec` is pinned by the
    /// `journal_format` tests in `anoma-rm-risc0`.
    pub fn to_journal(&self) -> Vec<u8> {
        let mut words: Vec<u32> = Vec::new();
        words.extend_from_slice(self.compliance_key.as_words());
        words.extend_from_slice(self.kind_tree_root.as_words());
        words.push(self.actions.len() as u32);
        for action in &self.actions {
            words.push(action.resources.len() as u32);
            for resource in &action.resources {
                words.push(resource.consumed);
                words.extend_from_slice(resource.tag.as_words());
                words.extend_from_slice(resource.logic_ref.as_words());
                words.extend_from_slice(resource.commitment_tree_root.as_words());
                resource.app_data.encode_journal(&mut words);
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
            for consumed in action.resources.iter().filter(|r| r.is_consumed()) {
                if !seen_nullifiers.insert(consumed.tag) {
                    return Err(crate::error::ArmError::NullifierDuplication);
                }
            }
        }
        Ok(())
    }
}

//! ARM (Anoma Resource Machine) library for resource management and transaction processing

#![deny(missing_docs)]

#[cfg(feature = "transaction")]
pub mod action;
pub mod action_tree;
#[cfg(any(feature = "compliance_circuit", feature = "aggregation_circuit"))]
pub mod compliance;
#[cfg(feature = "transaction")]
pub mod compliance_unit;
#[cfg(feature = "transaction")]
pub mod constants;
#[cfg(feature = "transaction")]
pub mod delta_proof;
pub mod error;
pub mod logic_instance;
#[cfg(feature = "transaction")]
pub mod logic_proof;
pub mod merkle_path;
pub mod nullifier_key;
#[cfg(feature = "transaction")]
pub mod proving_system;
pub mod resource;
pub mod resource_logic;
#[cfg(feature = "transaction")]
pub mod transaction;
pub mod utils;

pub use arm_core::{
    action::Action,
    compliance::{initial_root, ComplianceInstance, ComplianceInstanceWords},
    compliance_unit::ComplianceUnit,
    constants::{
        BATCH_AGGREGATION_VK_BYTES, COMPLIANCE_VK_BYTES, EMPTY_HASH_BYTES, PADDING_LOGIC_VK_BYTES,
    },
    delta_types::{DeltaProof as CoreDeltaProof, DeltaWitness as CoreDeltaWitness},
    error::ArmError,
    logic_instance::{AppData, ExpirableBlob, LogicInstance, LogicVerifierInputs},
    merkle_path::{padding_leaf, MerklePath},
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    transaction::{Delta, Transaction},
    utils::{bytes_to_words, words_to_bytes},
    Digest,
};

#[cfg(feature = "transaction")]
pub use crate::action::ActionExt;
#[cfg(any(feature = "compliance_circuit", feature = "aggregation_circuit"))]
pub use crate::compliance::{ComplianceInstanceExt, ComplianceInstanceJournalExt};
#[cfg(feature = "transaction")]
pub use crate::compliance_unit::ComplianceUnitExt;
#[cfg(feature = "transaction")]
pub use crate::logic_proof::LogicVerifierInputsExt;
pub use crate::merkle_path::MerklePathExt;
pub use crate::nullifier_key::NullifierKeyExt;
#[cfg(feature = "transaction")]
pub use crate::transaction::TransactionExt;

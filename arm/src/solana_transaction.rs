//! Solana-compatible transaction types for on-chain verification.
//!
//! These types are simpler data structures designed for on-chain use,
//! where proofs are verified but not generated.

use crate::compliance::ComplianceInstance;
use crate::logic_instance::AppData;
use crate::Digest;
use serde::{Deserialize, Serialize};

#[cfg(feature = "solana")]
use borsh::{BorshDeserialize, BorshSerialize};

/// Inputs for logic verification on-chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "solana", derive(BorshSerialize, BorshDeserialize))]
pub struct LogicVerifierInputs {
    /// The tag (nullifier or commitment) identifying this logic instance.
    pub tag: Digest,
    /// The verifying key for the logic proof.
    pub verifying_key: Digest,
    /// Application-specific data.
    pub app_data: AppData,
    /// The logic proof (None when using aggregated proofs).
    pub proof: Option<Vec<u8>>,
}

/// A compliance unit for on-chain verification.
/// Contains the deserialized instance directly (unlike the off-chain version
/// which stores serialized bytes).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "solana", derive(BorshSerialize, BorshDeserialize))]
pub struct ComplianceUnit {
    /// The compliance proof (None when using aggregated proofs).
    pub proof: Option<Vec<u8>>,
    /// The compliance instance (deserialized for on-chain access).
    pub instance: ComplianceInstance,
}

/// An action containing compliance units and logic verifier inputs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "solana", derive(BorshSerialize, BorshDeserialize))]
pub struct Action {
    /// The compliance units in this action.
    pub compliance_units: Vec<ComplianceUnit>,
    /// The logic verifier inputs in this action.
    pub logic_verifier_inputs: Vec<LogicVerifierInputs>,
}

/// Delta proof type for on-chain verification.
/// Uses raw bytes instead of typed witness/proof structures.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "solana", derive(BorshSerialize, BorshDeserialize))]
pub enum Delta {
    /// Delta witness bytes (for off-chain proving).
    Witness(Vec<u8>),
    /// Delta proof bytes (for on-chain verification).
    Proof(Vec<u8>),
}

/// A transaction for on-chain verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "solana", derive(BorshSerialize, BorshDeserialize))]
pub struct Transaction {
    /// The actions in this transaction.
    pub actions: Vec<Action>,
    /// The delta proof (witness or proof).
    pub delta_proof: Delta,
    /// Expected balance (placeholder, unbalanced transactions not supported).
    pub expected_balance: Option<Vec<u8>>,
    /// The aggregation proof bytes.
    pub aggregation_proof: Option<Vec<u8>>,
}

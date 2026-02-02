//! ARM (Anoma Resource Machine) library for resource management and transaction processing

#![deny(missing_docs)]

// When zkvm is enabled, use risc0's Digest for compatibility with risc0 APIs
#[cfg(feature = "zkvm")]
pub use risc0_zkvm::sha::{Digest, DIGEST_BYTES, DIGEST_WORDS};

// When zkvm is disabled (solana feature), use standalone Digest
#[cfg(not(feature = "zkvm"))]
mod digest;
#[cfg(not(feature = "zkvm"))]
pub use digest::{Digest, DIGEST_BYTES, DIGEST_WORDS};

#[cfg(feature = "transaction")]
pub mod action;
#[cfg(feature = "zkvm")]
pub mod action_tree;
#[cfg(feature = "aggregation")]
pub mod aggregation;
#[cfg(any(feature = "compliance_circuit", feature = "aggregation_circuit"))]
pub mod compliance;
#[cfg(feature = "transaction")]
pub mod compliance_unit;
#[cfg(feature = "transaction")]
pub mod constants;
#[cfg(feature = "transaction")]
pub mod delta_proof;
pub mod error;
#[cfg(feature = "aggregation_circuit")]
pub mod hash;
pub mod logic_instance;
#[cfg(feature = "transaction")]
pub mod logic_proof;
pub mod merkle_path;
pub mod nullifier_key;
#[cfg(feature = "transaction")]
pub mod proving_system;
#[cfg(feature = "zkvm")]
pub mod resource;
#[cfg(feature = "zkvm")]
pub mod resource_logic;
#[cfg(feature = "solana")]
pub mod solana_constants;
#[cfg(feature = "transaction")]
pub mod transaction;
pub mod utils;

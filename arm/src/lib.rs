//! ARM (Anoma Resource Machine) library for resource management and transaction processing

#![deny(missing_docs)]

// Conditional Digest: standalone when zkvm is off, risc0's when zkvm is on
#[cfg(not(feature = "zkvm"))]
mod digest;
#[cfg(not(feature = "zkvm"))]
pub use digest::{Digest, DIGEST_BYTES, DIGEST_WORDS};

#[cfg(feature = "zkvm")]
pub use risc0_zkvm::sha::{DIGEST_BYTES, DIGEST_WORDS};
#[cfg(feature = "zkvm")]
pub use risc0_zkvm::Digest;

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
pub mod constants;
#[cfg(all(feature = "transaction", feature = "k256"))]
pub mod delta_proof;
pub mod error;
#[cfg(feature = "aggregation_circuit")]
pub mod hash;
pub mod logic_instance;
#[cfg(all(feature = "transaction", feature = "zkvm"))]
pub mod logic_proof;
pub mod merkle_path;
pub mod nullifier_key;
#[cfg(all(feature = "transaction", feature = "zkvm"))]
pub mod proving_system;
#[cfg(feature = "zkvm")]
pub mod resource;
#[cfg(feature = "zkvm")]
pub mod resource_logic;
#[cfg(feature = "transaction")]
pub mod transaction;
pub mod utils;

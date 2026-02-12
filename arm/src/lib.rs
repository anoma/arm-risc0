//! ARM (Anoma Resource Machine) library for resource management and transaction processing

#![deny(missing_docs)]

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
#[cfg(any(feature = "compliance_circuit", feature = "aggregation_circuit"))]
pub mod compliance;
#[cfg(feature = "transaction")]
pub mod compliance_unit;
pub mod constants;
#[cfg(all(feature = "transaction", feature = "k256"))]
pub mod delta_proof;
#[cfg(feature = "transaction")]
pub mod delta_types;
pub mod error;
pub mod logic_instance;
#[cfg(all(feature = "transaction", feature = "zkvm", feature = "k256"))]
pub mod logic_proof;
pub mod merkle_path;
pub mod nullifier_key;
#[cfg(all(feature = "transaction", feature = "zkvm"))]
pub mod proving_system;
#[cfg(all(feature = "zkvm", feature = "k256"))]
pub mod resource;
#[cfg(all(feature = "zkvm", feature = "k256"))]
pub mod resource_logic;
#[cfg(feature = "transaction")]
pub mod transaction;
pub mod utils;

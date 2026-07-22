//! ARM (Anoma Resource Machine) library for resource management and transaction processing

#![deny(missing_docs)]

#[cfg(feature = "transaction")]
pub mod action;
pub mod action_tree;
pub mod aggregation_instance;
#[cfg(feature = "compliance_circuit")]
pub mod aggregation_witness;
#[cfg(feature = "compliance_circuit")]
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

pub use aggregation_instance::{
    ActionAggregated, AggregationInstance, ConsumedResourceAggregated, CreatedResourceAggregated,
};
pub use risc0_zkvm::Digest;

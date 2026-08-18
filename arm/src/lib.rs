//! ARM (Anoma Resource Machine) library for resource management and transaction processing

#![deny(missing_docs)]

pub mod action;
pub mod action_tree;
pub mod aggregation_instance;
#[cfg(feature = "compliance_circuit")]
pub mod aggregation_witness;
#[cfg(feature = "compliance_circuit")]
pub mod compliance;
pub mod compliance_unit;
pub mod constants;
pub mod delta_proof;
pub mod error;
pub mod logic_instance;
pub mod logic_proof;
pub mod merkle_path;
pub mod nullifier_key;
pub mod proving_system;
pub mod resource;
pub mod resource_logic;
pub mod transaction;
pub mod utils;

pub use aggregation_instance::{
    ActionAggregated, AggregationInstance, ConsumedResourceAggregated, CreatedResourceAggregated,
};
pub use risc0_zkp::core::digest::Digest;

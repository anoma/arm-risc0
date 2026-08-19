//! Anoma Resource Machine protocol data model — the engine-free core.
//!
//! This crate owns what the protocol's values *are*: the wire types, their
//! serialized forms, structural invariants, and the sha256-backed
//! derivations (commitments, nullifiers, tree roots). It owns none of what
//! you can *do* with them cryptographically — signing, curve arithmetic,
//! and proving live in engine crates (`anoma-rm-risc0` for host/zkVM,
//! `anoma-rm-solana` for Solana syscalls) — and its dependency graph
//! contains no cryptographic engine, so any consumer in any execution
//! environment can depend on it safely.

#![deny(missing_docs)]

pub mod action;
pub mod action_tree;
pub mod aggregation_instance;
pub mod aggregation_witness;
pub mod compliance;
pub mod compliance_unit;
pub mod constants;
pub mod delta_proof;
pub mod error;
pub mod logic_instance;
pub mod logic_proof;
pub mod merkle_path;
pub mod nullifier_key;
pub mod resource;
pub mod resource_logic;
pub mod transaction;
pub mod utils;

pub use risc0_zkp::core::digest::Digest;

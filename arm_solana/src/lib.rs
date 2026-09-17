//! Solana engine for the Anoma Resource Machine: transaction verification
//! over `anoma-rm-core`'s data model using the Solana runtime's native
//! primitives (keccak and secp256k1-recovery syscalls, `solana-secp256k1`
//! point arithmetic). The counterpart of the host/zkVM engine in
//! `anoma-rm-risc0` — same semantics, different execution environment;
//! cross-check tests pin the two engines to each other.

#![deny(missing_docs)]

pub mod delta;
pub mod error;
pub mod journal;

pub use error::SolanaArmError;

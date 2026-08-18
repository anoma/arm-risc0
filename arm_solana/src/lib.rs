//! Solana-specific ARM extensions: on-chain verification using Solana syscalls.

#![deny(missing_docs)]

pub mod delta;
pub mod error;
pub mod journal;

pub use error::SolanaArmError;

//! Solana-specific constants for verification keys.
//!
//! These constants are exported when the `solana` feature is enabled.
//! They use byte arrays instead of risc0_zkvm::Digest for Solana compatibility.

use crate::Digest;

/// Compliance verification key bytes (Solana-serializing circuit).
pub const COMPLIANCE_VK_BYTES: [u8; 32] =
    hex_literal::hex!("1176e7f038c55009f369e2eafd1dd9bc5b51a6f5fc6369cc9f54779258f898fc");

/// Batch aggregation verification key bytes (Borsh-serializing circuit).
pub const BATCH_AGGREGATION_VK_BYTES: [u8; 32] =
    hex_literal::hex!("0235fd42c773897d07063ad9515723e2ea8d7f54a786b230b5395fd73071d8d3");

/// Returns the compliance verification key as a Digest.
pub fn compliance_vk() -> Digest {
    Digest::from_bytes(COMPLIANCE_VK_BYTES)
}

/// Returns the batch aggregation verification key as a Digest.
pub fn batch_aggregation_vk() -> Digest {
    Digest::from_bytes(BATCH_AGGREGATION_VK_BYTES)
}

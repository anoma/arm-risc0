//! Solana-specific constants for verification keys.
//!
//! These constants are exported when the `solana` feature is enabled.
//! They use byte arrays instead of risc0_zkvm::Digest for Solana compatibility.

use crate::Digest;

/// Compliance verification key bytes (Solana-serializing circuit).
pub const COMPLIANCE_VK_BYTES: [u8; 32] =
    hex_literal::hex!("1176e7f038c55009f369e2eafd1dd9bc5b51a6f5fc6369cc9f54779258f898fc");

/// Batch aggregation verification key bytes (Solana-serializing circuit).
pub const BATCH_AGGREGATION_VK_BYTES: [u8; 32] =
    hex_literal::hex!("4297db7ea74c296acd49ca55e160a6e930478da2605931ea0654d466c0f95099");

/// Returns the compliance verification key as a Digest.
pub fn compliance_vk() -> Digest {
    Digest::from_bytes(COMPLIANCE_VK_BYTES)
}

/// Returns the batch aggregation verification key as a Digest.
pub fn batch_aggregation_vk() -> Digest {
    Digest::from_bytes(BATCH_AGGREGATION_VK_BYTES)
}

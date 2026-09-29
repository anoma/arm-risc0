//! Verification-key digests (guest image IDs) for the ARM circuits.
//!
//! `const` rather than lazy statics: statics with interior mutability
//! compile to writable `.bss` sections, which the Solana loader rejects at
//! deploy time. Each value is pinned against `Digest::from_hex` of its
//! canonical hex form in tests, and all of them are regenerated together
//! with the guest ELFs whenever the circuits change.
//!
//! The proving keys (the guest ELF binaries themselves) live in the
//! host/zkVM engine crate — they are prover-side artifacts and would bloat
//! every non-proving consumer.

use risc0_zkp::core::digest::Digest;

/// Compliance verification key / compliance image id,
/// db0af6c6ab79c157d7fbf9baf8e9c9cbad3d63363eae75ae36373225cbbba7ec.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xc6f60adb, 0x57c179ab, 0xbaf9fbd7, 0xcbc9e9f8, 0x36633dad, 0xae75ae3e, 0x25323736, 0xeca7bbcb,
]);

/// Padding logic verification key / padding image id,
/// 8fb0038cd3a02e7f61c97183a06edaa7960881a39c2e92ef8c4fcb69feada341.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x8c03b08f, 0x7f2ea0d3, 0x8371c961, 0xa7da6ea0, 0xa3810896, 0xef922e9c, 0x69cb4f8c, 0x41a3adfe,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 1151a309d3b32816c8f45e9edf8d8c9912630dfd7e1bfcc0679928fe84ea8b30.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x09a35111, 0x1628b3d3, 0x9e5ef4c8, 0x998c8ddf, 0xfd0d6312, 0xc0fc1b7e, 0xfe289967, 0x308bea84,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// eedcc3d96dda94b486de356f5f3519a63f29aac2b02bb048f736238f812d703d.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0xd9c3dcee, 0xb494da6d, 0x6f35de86, 0xa619355f, 0xc2aa293f, 0x48b02bb0, 0x8f2336f7, 0x3d702d81,
]);

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn vk_consts_match_hex() {
        for (name, konst, hex) in [
            (
                "COMPLIANCE_VK",
                COMPLIANCE_VK,
                "db0af6c6ab79c157d7fbf9baf8e9c9cbad3d63363eae75ae36373225cbbba7ec",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "8fb0038cd3a02e7f61c97183a06edaa7960881a39c2e92ef8c4fcb69feada341",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "1151a309d3b32816c8f45e9edf8d8c9912630dfd7e1bfcc0679928fe84ea8b30",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "eedcc3d96dda94b486de356f5f3519a63f29aac2b02bb048f736238f812d703d",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

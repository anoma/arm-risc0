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
/// 406c60f87a5bb542a7fc7301ba5c01fe7724b5b3c9e335214d092a10b405f5a0.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xf8606c40, 0x42b55b7a, 0x0173fca7, 0xfe015cba, 0xb3b52477, 0x2135e3c9, 0x102a094d, 0xa0f505b4,
]);

/// Padding logic verification key / padding image id,
/// 5de2a1afac74d1f6fc3ff149cb6ab553044a1467346fbe8775cb4988a6f63cbc.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0xafa1e25d, 0xf6d174ac, 0x49f13ffc, 0x53b56acb, 0x67144a04, 0x87be6f34, 0x8849cb75, 0xbc3cf6a6,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 26062b168bd20222a8911dd523b3310862411eccd636956b178e701f48245087.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x162b0626, 0x2202d28b, 0xd51d91a8, 0x0831b323, 0xcc1e4162, 0x6b9536d6, 0x1f708e17, 0x87502448,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 858be23ecbd24b70efdfacada11c2f0471f33982e33758b8861e5d462576dc46.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x3ee28b85, 0x704bd2cb, 0xadacdfef, 0x042f1ca1, 0x8239f371, 0xb85837e3, 0x465d1e86, 0x46dc7625,
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
                "406c60f87a5bb542a7fc7301ba5c01fe7724b5b3c9e335214d092a10b405f5a0",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "5de2a1afac74d1f6fc3ff149cb6ab553044a1467346fbe8775cb4988a6f63cbc",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "26062b168bd20222a8911dd523b3310862411eccd636956b178e701f48245087",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "858be23ecbd24b70efdfacada11c2f0471f33982e33758b8861e5d462576dc46",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

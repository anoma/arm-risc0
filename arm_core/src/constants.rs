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
/// 7b657df4c7ee3ef8592894761aefc80f196e5b97dd27d43a98628b2ce2ef91f0.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xf47d657b, 0xf83eeec7, 0x76942859, 0x0fc8ef1a, 0x975b6e19, 0x3ad427dd, 0x2c8b6298, 0xf091efe2,
]);

/// Padding logic verification key / padding image id,
/// 034c170fc2045f5e257110eb369e57ea5dc72d6dd83dab69746afc2bec6e1847.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x0f174c03, 0x5e5f04c2, 0xeb107125, 0xea579e36, 0x6d2dc75d, 0x69ab3dd8, 0x2bfc6a74, 0x47186eec,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 9557c17ec8607f788e184991363992233c28a7d7013605579baa7145815f5497.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x7ec15795, 0x787f60c8, 0x9149188e, 0x23923936, 0xd7a7283c, 0x57053601, 0x4571aa9b, 0x97545f81,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// a46d8bf487ebfdbe1d611a766b6a3fcb2884d2f226b3ce629f2bf25c411bce91.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0xf48b6da4, 0xbefdeb87, 0x761a611d, 0xcb3f6a6b, 0xf2d28428, 0x62ceb326, 0x5cf22b9f, 0x91ce1b41,
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
                "7b657df4c7ee3ef8592894761aefc80f196e5b97dd27d43a98628b2ce2ef91f0",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "034c170fc2045f5e257110eb369e57ea5dc72d6dd83dab69746afc2bec6e1847",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "9557c17ec8607f788e184991363992233c28a7d7013605579baa7145815f5497",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "a46d8bf487ebfdbe1d611a766b6a3fcb2884d2f226b3ce629f2bf25c411bce91",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

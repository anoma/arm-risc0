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
/// ea64f106d0f38b536bb1afab99b2ccb6c84ca3fd33a8b4f0ee6a15e5596632b8.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0x06f164ea, 0x538bf3d0, 0xabafb16b, 0xb6ccb299, 0xfda34cc8, 0xf0b4a833, 0xe5156aee, 0xb8326659,
]);

/// Padding logic verification key / padding image id,
/// ce036f2a8e21367fb51433693f299e0a1ef9e0060ceadb18fae6c78ac465d9ad.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x2a6f03ce, 0x7f36218e, 0x693314b5, 0x0a9e293f, 0x06e0f91e, 0x18dbea0c, 0x8ac7e6fa, 0xadd965c4,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// ff4673f39f383d0109d5b8af4dd693c0f8275a809416d49a4cedd0a1b8389998.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0xf37346ff, 0x013d389f, 0xafb8d509, 0xc093d64d, 0x805a27f8, 0x9ad41694, 0xa1d0ed4c, 0x989938b8,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 48aaf4d257ccddf8aeea01ca256d14193f2ac278c5e084f7d897c527d5ed9657.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0xd2f4aa48, 0xf8ddcc57, 0xca01eaae, 0x19146d25, 0x78c22a3f, 0xf784e0c5, 0x27c597d8, 0x5796edd5,
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
                "ea64f106d0f38b536bb1afab99b2ccb6c84ca3fd33a8b4f0ee6a15e5596632b8",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "ce036f2a8e21367fb51433693f299e0a1ef9e0060ceadb18fae6c78ac465d9ad",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "ff4673f39f383d0109d5b8af4dd693c0f8275a809416d49a4cedd0a1b8389998",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "48aaf4d257ccddf8aeea01ca256d14193f2ac278c5e084f7d897c527d5ed9657",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

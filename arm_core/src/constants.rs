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
/// 23e01dda73611df43ef58e427133f8fdded73a26e0b8b950a616beb2318cdb76.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xda1de023, 0xf41d6173, 0x428ef53e, 0xfdf83371, 0x263ad7de, 0x50b9b8e0, 0xb2be16a6, 0x76db8c31,
]);

/// Padding logic verification key / padding image id,
/// b6cb7fcdf12a0413da86c4edea128bec945f82071f1c268bc16ef89ba931cca5.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0xcd7fcbb6, 0x13042af1, 0xedc486da, 0xec8b12ea, 0x07825f94, 0x8b261c1f, 0x9bf86ec1, 0xa5cc31a9,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 0c805c99e67b653672463c13a1c8c7b14241cf49f7f9a56ba9a829683fe13948.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x995c800c, 0x36657be6, 0x133c4672, 0xb1c7c8a1, 0x49cf4142, 0x6ba5f9f7, 0x6829a8a9, 0x4839e13f,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// a76ad2f5b2989aceb0320d604c2425be30fac04e855d6ce1dec8f731601ab3d4.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0xf5d26aa7, 0xce9a98b2, 0x600d32b0, 0xbe25244c, 0x4ec0fa30, 0xe16c5d85, 0x31f7c8de, 0xd4b31a60,
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
                "23e01dda73611df43ef58e427133f8fdded73a26e0b8b950a616beb2318cdb76",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "b6cb7fcdf12a0413da86c4edea128bec945f82071f1c268bc16ef89ba931cca5",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "0c805c99e67b653672463c13a1c8c7b14241cf49f7f9a56ba9a829683fe13948",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "a76ad2f5b2989aceb0320d604c2425be30fac04e855d6ce1dec8f731601ab3d4",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

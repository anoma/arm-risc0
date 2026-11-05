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
/// c80bce00808b3c99e0e49ed9f35641a0f2c0cb33646f1845bce70d3792eb7c2a.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0x00ce0bc8, 0x993c8b80, 0xd99ee4e0, 0xa04156f3, 0x33cbc0f2, 0x45186f64, 0x370de7bc, 0x2a7ceb92,
]);

/// Padding logic verification key / padding image id,
/// a5cf4450ba98bc61e8cc0dd499175860c7baf9917dce6ef2e64b807bba8eb8fc.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x5044cfa5, 0x61bc98ba, 0xd40dcce8, 0x60581799, 0x91f9bac7, 0xf26ece7d, 0x7b804be6, 0xfcb88eba,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// cb0aed136e9c5d3732e102db330e1d8b9a82f63a223b656d0c1e4652acef8a46.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x13ed0acb, 0x375d9c6e, 0xdb02e132, 0x8b1d0e33, 0x3af6829a, 0x6d653b22, 0x52461e0c, 0x468aefac,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 103c0ed3d083706f43f12f3c153b48da68543b13db2a0e2342fc4abe1819172f.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0xd30e3c10, 0x6f7083d0, 0x3c2ff143, 0xda483b15, 0x133b5468, 0x230e2adb, 0xbe4afc42, 0x2f171918,
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
                "c80bce00808b3c99e0e49ed9f35641a0f2c0cb33646f1845bce70d3792eb7c2a",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "a5cf4450ba98bc61e8cc0dd499175860c7baf9917dce6ef2e64b807bba8eb8fc",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "cb0aed136e9c5d3732e102db330e1d8b9a82f63a223b656d0c1e4652acef8a46",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "103c0ed3d083706f43f12f3c153b48da68543b13db2a0e2342fc4abe1819172f",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

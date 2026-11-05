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
/// 3dd727cb7f31e78bd9d1c25bf61b31a918028e40a30fa002b2c9b74f7be03c3e.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xcb27d73d, 0x8be7317f, 0x5bc2d1d9, 0xa9311bf6, 0x408e0218, 0x02a00fa3, 0x4fb7c9b2, 0x3e3ce07b,
]);

/// Padding logic verification key / padding image id,
/// 0670cc5b9bd81135ca9ee9f047347616077875de48b2c655336d2bb80d38adb4.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x5bcc7006, 0x3511d89b, 0xf0e99eca, 0x16763447, 0xde757807, 0x55c6b248, 0xb82b6d33, 0xb4ad380d,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 6a1e5bf6f4cfab5637d76571ac50bd018be7a79f6a36aac0db32e3d8fc1b49c7.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0xf65b1e6a, 0x56abcff4, 0x7165d737, 0x01bd50ac, 0x9fa7e78b, 0xc0aa366a, 0xd8e332db, 0xc7491bfc,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 67191115444072d9a035e9d4997a2ecde01615b76d158d22030f2added0f2377.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x15111967, 0xd9724044, 0xd4e935a0, 0xcd2e7a99, 0xb71516e0, 0x228d156d, 0xdd2a0f03, 0x77230fed,
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
                "3dd727cb7f31e78bd9d1c25bf61b31a918028e40a30fa002b2c9b74f7be03c3e",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "0670cc5b9bd81135ca9ee9f047347616077875de48b2c655336d2bb80d38adb4",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "6a1e5bf6f4cfab5637d76571ac50bd018be7a79f6a36aac0db32e3d8fc1b49c7",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "67191115444072d9a035e9d4997a2ecde01615b76d158d22030f2added0f2377",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

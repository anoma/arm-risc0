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
/// bb673291882eb2bb712d34000c0d1302ed97c8435c730595c39e65c8c167bde6.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0x913267bb, 0xbbb22e88, 0x00342d71, 0x02130d0c, 0x43c897ed, 0x9505735c, 0xc8659ec3, 0xe6bd67c1,
]);

/// Padding logic verification key / padding image id,
/// 2ba12576f5caf1149c18fe98b35c56adecc9ffaf39eafef49ea050e38d04d012.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x7625a12b, 0x14f1caf5, 0x98fe189c, 0xad565cb3, 0xafffc9ec, 0xf4feea39, 0xe350a09e, 0x12d0048d,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 8d353f30d87d83c20e149a2d056ef8887e2e2bb70d16705c815af2e0f47aaea1.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x303f358d, 0xc2837dd8, 0x2d9a140e, 0x88f86e05, 0xb72b2e7e, 0x5c70160d, 0xe0f25a81, 0xa1ae7af4,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// dcaf2ecd6ef4563cc1a155985af4544ba4f72153ac764b432ae383d48c91afea.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0xcd2eafdc, 0x3c56f46e, 0x9855a1c1, 0x4b54f45a, 0x5321f7a4, 0x434b76ac, 0xd483e32a, 0xeaaf918c,
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
                "bb673291882eb2bb712d34000c0d1302ed97c8435c730595c39e65c8c167bde6",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "2ba12576f5caf1149c18fe98b35c56adecc9ffaf39eafef49ea050e38d04d012",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "8d353f30d87d83c20e149a2d056ef8887e2e2bb70d16705c815af2e0f47aaea1",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "dcaf2ecd6ef4563cc1a155985af4544ba4f72153ac764b432ae383d48c91afea",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

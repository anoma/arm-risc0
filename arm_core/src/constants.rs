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
/// 0ebc6c35680d6c45d27f0686aaa3a4d0331220c5bd2e52ce1195a5bce1033e08.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0x356cbc0e, 0x456c0d68, 0x86067fd2, 0xd0a4a3aa, 0xc5201233, 0xce522ebd, 0xbca59511, 0x083e03e1,
]);

/// Padding logic verification key / padding image id,
/// 2ba12576f5caf1149c18fe98b35c56adecc9ffaf39eafef49ea050e38d04d012.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x7625a12b, 0x14f1caf5, 0x98fe189c, 0xad565cb3, 0xafffc9ec, 0xf4feea39, 0xe350a09e, 0x12d0048d,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 67cbed251d050af93bb19910bc817414d5419a3e760234463e1c50a426f4f0f2.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x25edcb67, 0xf90a051d, 0x1099b13b, 0x147481bc, 0x3e9a41d5, 0x46340276, 0xa4501c3e, 0xf2f0f426,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 896fd82f0d437a4c50a3d9986bcc1c03bb4f9e9bf83b0243dbb5907dd98b6cb6.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x2fd86f89, 0x4c7a430d, 0x98d9a350, 0x031ccc6b, 0x9b9e4fbb, 0x43023bf8, 0x7d90b5db, 0xb66c8bd9,
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
                "0ebc6c35680d6c45d27f0686aaa3a4d0331220c5bd2e52ce1195a5bce1033e08",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "2ba12576f5caf1149c18fe98b35c56adecc9ffaf39eafef49ea050e38d04d012",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "67cbed251d050af93bb19910bc817414d5419a3e760234463e1c50a426f4f0f2",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "896fd82f0d437a4c50a3d9986bcc1c03bb4f9e9bf83b0243dbb5907dd98b6cb6",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

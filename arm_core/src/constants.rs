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
/// 3c76e65f2e225756d29f23e8b79bcd88fc10ae4365af517993c9a28ceb37d35f.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0x5fe6763c, 0x5657222e, 0xe8239fd2, 0x88cd9bb7, 0x43ae10fc, 0x7951af65, 0x8ca2c993, 0x5fd337eb,
]);

/// Padding logic verification key / padding image id,
/// d08ebfdef08d284574d5259098d011a6eeb9889d0367b860ccd18fdf5fd2a927.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0xdebf8ed0, 0x45288df0, 0x9025d574, 0xa611d098, 0x9d88b9ee, 0x60b86703, 0xdf8fd1cc, 0x27a9d25f,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 8c17585d0945912d1c182a6b9e14f2a9d9a4990d1d0ce55bb6c894319251e50c.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x5d58178c, 0x2d914509, 0x6b2a181c, 0xa9f2149e, 0x0d99a4d9, 0x5be50c1d, 0x3194c8b6, 0x0ce55192,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 2ecf4b3ce5cc0d949639cddba250d31cf592470c41c2e5f881eed5c3938c35b8.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x3c4bcf2e, 0x940dcce5, 0xdbcd3996, 0x1cd350a2, 0x0c4792f5, 0xf8e5c241, 0xc3d5ee81, 0xb8358c93,
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
                "3c76e65f2e225756d29f23e8b79bcd88fc10ae4365af517993c9a28ceb37d35f",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "d08ebfdef08d284574d5259098d011a6eeb9889d0367b860ccd18fdf5fd2a927",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "8c17585d0945912d1c182a6b9e14f2a9d9a4990d1d0ce55bb6c894319251e50c",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "2ecf4b3ce5cc0d949639cddba250d31cf592470c41c2e5f881eed5c3938c35b8",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

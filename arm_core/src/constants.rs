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
/// bdb9cd903dbac3cd454a9cf7a145f5390b24f90d3fbc9420232339b7faf20be6.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0x90cdb9bd, 0xcdc3ba3d, 0xf79c4a45, 0x39f545a1, 0x0df9240b, 0x2094bc3f, 0xb7392323, 0xe60bf2fa,
]);

/// Padding logic verification key / padding image id,
/// d61308b559b3c90b74d329e75de2ac019d30f4235ec4fdc056d3e822518e6a51.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0xb50813d6, 0x0bc9b359, 0xe729d374, 0x01ace25d, 0x23f4309d, 0xc0fdc45e, 0x22e8d356, 0x516a8e51,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 592dafdbaa7c5ff661ab84650909d3447a88891ddd327fedb7e799e4831f8cf7.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0xdbaf2d59, 0xf65f7caa, 0x6584ab61, 0x44d30909, 0x1d89887a, 0xed7f32dd, 0xe499e7b7, 0xf78c1f83,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// ecb83e9d3053617831ad6809c0ec018df7ee94f540892ceaa7eb5b62861d0bca.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x9d3eb8ec, 0x78615330, 0x0968ad31, 0x8d01ecc0, 0xf594eef7, 0xea2c8940, 0x625beba7, 0xca0b1d86,
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
                "bdb9cd903dbac3cd454a9cf7a145f5390b24f90d3fbc9420232339b7faf20be6",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "d61308b559b3c90b74d329e75de2ac019d30f4235ec4fdc056d3e822518e6a51",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "592dafdbaa7c5ff661ab84650909d3447a88891ddd327fedb7e799e4831f8cf7",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "ecb83e9d3053617831ad6809c0ec018df7ee94f540892ceaa7eb5b62861d0bca",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

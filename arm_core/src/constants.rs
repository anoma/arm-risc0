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
/// 4b96ebb3511e7f7352ea48553fe1a2cf6a3e085816752bb7c116be2073838770.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xb3eb964b, 0x737f1e51, 0x5548ea52, 0xcfa2e13f, 0x58083e6a, 0xb72b7516, 0x20be16c1, 0x70878373,
]);

/// Padding logic verification key / padding image id,
/// 28c43d58b113f1e66abdda1399cfebd49baa17de1ab2b7a0d1d39645efeb7262.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x583dc428, 0xe6f113b1, 0x13dabd6a, 0xd4ebcf99, 0xde17aa9b, 0xa0b7b21a, 0x4596d3d1, 0x6272ebef,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// c30d83a533f76b27a52e48173d15e3f2c2d1316e624e39648fd8358fdc274a40.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0xa5830dc3, 0x276bf733, 0x17482ea5, 0xf2e3153d, 0x6e31d1c2, 0x64394e62, 0x8f35d88f, 0x404a27dc,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 3f3e4564737b10f9003d5979a9602092e164a611dc294031e34e8f116c3913f3.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x64453e3f, 0xf9107b73, 0x79593d00, 0x922060a9, 0x11a664e1, 0x314029dc, 0x118f4ee3, 0xf313396c,
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
                "4b96ebb3511e7f7352ea48553fe1a2cf6a3e085816752bb7c116be2073838770",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "28c43d58b113f1e66abdda1399cfebd49baa17de1ab2b7a0d1d39645efeb7262",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "c30d83a533f76b27a52e48173d15e3f2c2d1316e624e39648fd8358fdc274a40",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "3f3e4564737b10f9003d5979a9602092e164a611dc294031e34e8f116c3913f3",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

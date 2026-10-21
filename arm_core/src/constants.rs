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
/// bc4edaeea98f6501547cba34cf94d8b59631e7f86cf1a47119ba6f17c29a517c.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xeeda4ebc, 0x01658fa9, 0x34ba7c54, 0xb5d894cf, 0xf8e73196, 0x71a4f16c, 0x176fba19, 0x7c519ac2,
]);

/// Padding logic verification key / padding image id,
/// 832647d733fe19cec6de0cbb30f2f58d3927445a591e2ddb2851a43901dc1d51.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0xd7472683, 0xce19fe33, 0xbb0cdec6, 0x8df5f230, 0x5a442739, 0xdb2d1e59, 0x39a45128, 0x511ddc01,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// f94aa2e3eb7827439339f4339f861f222a439a8fb3364fad22741591b2d8c5e8.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0xe3a24af9, 0x432778eb, 0x33f43993, 0x221f869f, 0x8f9a432a, 0xad4f36b3, 0x91157422, 0xe8c5d8b2,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 35082a39ecba805a1ca4fdac7eb364b20afce2abf14413ebd910233332ee45c9.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x392a0835, 0x5a80baec, 0xacfda41c, 0xb264b37e, 0xabe2fc0a, 0xeb1344f1, 0x332310d9, 0xc945ee32,
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
                "bc4edaeea98f6501547cba34cf94d8b59631e7f86cf1a47119ba6f17c29a517c",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "832647d733fe19cec6de0cbb30f2f58d3927445a591e2ddb2851a43901dc1d51",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "f94aa2e3eb7827439339f4339f861f222a439a8fb3364fad22741591b2d8c5e8",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "35082a39ecba805a1ca4fdac7eb364b20afce2abf14413ebd910233332ee45c9",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

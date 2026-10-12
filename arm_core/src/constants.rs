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
/// 88a8a2c28fb7f3b72b744aaedb413928ab84fa913626cd11b5ff0c7d4da0bcd5.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xc2a2a888, 0xb7f3b78f, 0xae4a742b, 0x283941db, 0x91fa84ab, 0x11cd2636, 0x7d0cffb5, 0xd5bca04d,
]);

/// Padding logic verification key / padding image id,
/// 5de2a1afac74d1f6fc3ff149cb6ab553044a1467346fbe8775cb4988a6f63cbc.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0xafa1e25d, 0xf6d174ac, 0x49f13ffc, 0x53b56acb, 0x67144a04, 0x87be6f34, 0x8849cb75, 0xbc3cf6a6,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// bb70f4ec07c5ca6c7a2b7d037ade92e0a377debec941f11b76b52d14f5b8ff21.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0xecf470bb, 0x6ccac507, 0x037d2b7a, 0xe092de7a, 0xbede77a3, 0x1bf141c9, 0x142db576, 0x21ffb8f5,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 57c433a0e42630708cdf57118e6b8f6b80a877c073c2bab6cd3492d07cf9ea79.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0xa033c457, 0x703026e4, 0x1157df8c, 0x6b8f6b8e, 0xc077a880, 0xb6bac273, 0xd09234cd, 0x79eaf97c,
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
                "88a8a2c28fb7f3b72b744aaedb413928ab84fa913626cd11b5ff0c7d4da0bcd5",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "5de2a1afac74d1f6fc3ff149cb6ab553044a1467346fbe8775cb4988a6f63cbc",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "bb70f4ec07c5ca6c7a2b7d037ade92e0a377debec941f11b76b52d14f5b8ff21",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "57c433a0e42630708cdf57118e6b8f6b80a877c073c2bab6cd3492d07cf9ea79",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

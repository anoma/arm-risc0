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
/// 78482ab858bc1efad251cf56f069617560e5aa22995028dcc2af3c95317cf153.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xb82a4878, 0xfa1ebc58, 0x56cf51d2, 0x756169f0, 0x22aae560, 0xdc285099, 0x953cafc2, 0x53f17c31,
]);

/// Padding logic verification key / padding image id,
/// 894ae75b75dbf24d389148effe6c57bd67957772200abcd51d33b0b0a4a7b712.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x5be74a89, 0x4df2db75, 0xef489138, 0xbd576cfe, 0x72779567, 0xd5bc0a20, 0xb0b0331d, 0x12b7a7a4,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 77eb979cc8d564b919329bae0ed1b85700be0599daa10b5729ba88a552ec8b44.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x9c97eb77, 0xb964d5c8, 0xae9b3219, 0x57b8d10e, 0x9905be00, 0x570ba1da, 0xa588ba29, 0x448bec52,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 8d67ea01f260cb401398c0d0f202cd30b281fd8d6f46ce8173cc93e2f1f65d43.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x01ea678d, 0x40cb60f2, 0xd0c09813, 0x30cd02f2, 0x8dfd81b2, 0x81ce466f, 0xe293cc73, 0x435df6f1,
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
                "78482ab858bc1efad251cf56f069617560e5aa22995028dcc2af3c95317cf153",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "894ae75b75dbf24d389148effe6c57bd67957772200abcd51d33b0b0a4a7b712",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "77eb979cc8d564b919329bae0ed1b85700be0599daa10b5729ba88a552ec8b44",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "8d67ea01f260cb401398c0d0f202cd30b281fd8d6f46ce8173cc93e2f1f65d43",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

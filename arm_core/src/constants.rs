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
/// 6a09c1ab13338d0361eb867468280aae67541e5aecc7a3bd4f885a7e189e3049.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xabc1096a, 0x038d3313, 0x7486eb61, 0xae0a2868, 0x5a1e5467, 0xbda3c7ec, 0x7e5a884f, 0x49309e18,
]);

/// Padding logic verification key / padding image id,
/// 7421e29e44360f11f05c1c754aa47830b0363f9d1cd23d02ba9364c2b521a4e1.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x9ee22174, 0x110f3644, 0x751c5cf0, 0x3078a44a, 0x9d3f36b0, 0x023dd21c, 0xc26493ba, 0xe1a421b5,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 6df7924211cfb7aacc654795cbc94e12b54a4bccecf3ed4d299e9ed3ef6a23c3.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x4292f76d, 0xaab7cf11, 0x954765cc, 0x124ec9cb, 0xcc4b4ab5, 0x4dedf3ec, 0xd39e9e29, 0xc3236aef,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// e639f52655d936a44444b49dcf8d446b3c0a72f79f2354476faad70d1f234e8e.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x26f539e6, 0xa436d955, 0x9db44444, 0x6b448dcf, 0xf7720a3c, 0x4754239f, 0x0dd7aa6f, 0x8e4e231f,
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
                "6a09c1ab13338d0361eb867468280aae67541e5aecc7a3bd4f885a7e189e3049",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "7421e29e44360f11f05c1c754aa47830b0363f9d1cd23d02ba9364c2b521a4e1",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "6df7924211cfb7aacc654795cbc94e12b54a4bccecf3ed4d299e9ed3ef6a23c3",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "e639f52655d936a44444b49dcf8d446b3c0a72f79f2354476faad70d1f234e8e",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

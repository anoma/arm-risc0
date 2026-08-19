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
/// c78ec30586ae4b9439676a0f699e361478180206da226f5283d9ba956f04bf02.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0x05c38ec7, 0x944bae86, 0x0f6a6739, 0x14369e69, 0x06021878, 0x526f22da, 0x95bad983, 0x02bf046f,
]);

/// Padding logic verification key / padding image id,
/// f5490a6510393944e1875fb6831c31e426b4971caff854c9f3081f755c826f6f.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x650a49f5, 0x44393910, 0xb65f87e1, 0xe4311c83, 0x1c97b426, 0xc954f8af, 0x751f08f3, 0x6f6f825c,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 55d2111cba5a9e2fb3512ae6276a465979a1ba4139e1745e4dc97ea638109c05.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x1c11d255, 0x2f9e5aba, 0xe62a51b3, 0x59466a27, 0x41baa179, 0x5e74e139, 0xa67ec94d, 0x059c1038,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 8a96908d5c8424a1a557b9fdfc744a7a327e7a9eb27d3520d7d66d4f1265ea4a.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x8d90968a, 0xa124845c, 0xfdb957a5, 0x7a4a74fc, 0x9e7a7e32, 0x20357db2, 0x4f6dd6d7, 0x4aea6512,
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
                "c78ec30586ae4b9439676a0f699e361478180206da226f5283d9ba956f04bf02",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "f5490a6510393944e1875fb6831c31e426b4971caff854c9f3081f755c826f6f",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "55d2111cba5a9e2fb3512ae6276a465979a1ba4139e1745e4dc97ea638109c05",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "8a96908d5c8424a1a557b9fdfc744a7a327e7a9eb27d3520d7d66d4f1265ea4a",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

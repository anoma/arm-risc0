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
/// 6e6212b6ee472d570d5211be106d93ebe6e8c7a58172bc17d886376e5201642a.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xb612626e, 0x572d47ee, 0xbe11520d, 0xeb936d10, 0xa5c7e8e6, 0x17bc7281, 0x6e3786d8, 0x2a640152,
]);

/// Padding logic verification key / padding image id,
/// 832647d733fe19cec6de0cbb30f2f58d3927445a591e2ddb2851a43901dc1d51.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0xd7472683, 0xce19fe33, 0xbb0cdec6, 0x8df5f230, 0x5a442739, 0xdb2d1e59, 0x39a45128, 0x511ddc01,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// bdb6de19adea398bc06beca913364db2875817f061d346eb337ab78e6e06d3ec.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x19deb6bd, 0x8b39eaad, 0xa9ec6bc0, 0xb24d3613, 0xf0175887, 0xeb46d361, 0x8eb77a33, 0xecd3066e,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 188fc422e8970c42fe61d5119e94e3537d7819ace008257f52060cf31b72b992.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x22c48f18, 0x420c97e8, 0x11d561fe, 0x53e3949e, 0xac19787d, 0x7f2508e0, 0xf30c0652, 0x92b9721b,
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
                "6e6212b6ee472d570d5211be106d93ebe6e8c7a58172bc17d886376e5201642a",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "832647d733fe19cec6de0cbb30f2f58d3927445a591e2ddb2851a43901dc1d51",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "bdb6de19adea398bc06beca913364db2875817f061d346eb337ab78e6e06d3ec",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "188fc422e8970c42fe61d5119e94e3537d7819ace008257f52060cf31b72b992",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

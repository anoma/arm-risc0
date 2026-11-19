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
/// 5f337810d11c37f60cde3e52a0b0bc3fc4516fa3daf94c7f24a359efefe86cc8.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0x1078335f, 0xf6371cd1, 0x523ede0c, 0x3fbcb0a0, 0xa36f51c4, 0x7f4cf9da, 0xef59a324, 0xc86ce8ef,
]);

/// Padding logic verification key / padding image id,
/// f89e46714963f36128f3954890e30e6c85212c3a33c57714664d85741e7cc78e.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x71469ef8, 0x61f36349, 0x4895f328, 0x6c0ee390, 0x3a2c2185, 0x1477c533, 0x74854d66, 0x8ec77c1e,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 2c6cb11fa4c84623245fe83833b2762128ea90986d137a10bf648e56d5b1d74a.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0x1fb16c2c, 0x2346c8a4, 0x38e85f24, 0x2176b233, 0x9890ea28, 0x107a136d, 0x568e64bf, 0x4ad7b1d5,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 40043e08c0f46c84453d0c7980fd53d6adba87522e5fac80b481e8c72df64da1.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x083e0440, 0x846cf4c0, 0x790c3d45, 0xd653fd80, 0x5287baad, 0x80ac5f2e, 0xc7e881b4, 0xa14df62d,
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
                "5f337810d11c37f60cde3e52a0b0bc3fc4516fa3daf94c7f24a359efefe86cc8",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "f89e46714963f36128f3954890e30e6c85212c3a33c57714664d85741e7cc78e",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "2c6cb11fa4c84623245fe83833b2762128ea90986d137a10bf648e56d5b1d74a",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "40043e08c0f46c84453d0c7980fd53d6adba87522e5fac80b481e8c72df64da1",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

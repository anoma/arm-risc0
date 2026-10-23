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
/// 6771d2b47a3c3f40a1a2e635b2ddf0db3159e95856879e4e8d0a665025b0026b.
pub const COMPLIANCE_VK: Digest = Digest::new([
    0xb4d27167, 0x403f3c7a, 0x35e6a2a1, 0xdbf0ddb2, 0x58e95931, 0x4e9e8756, 0x50660a8d, 0x6b02b025,
]);

/// Padding logic verification key / padding image id,
/// 662a8c3eccff1958d3248c9d395fb52e63597148022c69b70934f6247a820940.
pub const PADDING_LOGIC_VK: Digest = Digest::new([
    0x3e8c2a66, 0x5819ffcc, 0x9d8c24d3, 0x2eb55f39, 0x48715963, 0xb7692c02, 0x24f63409, 0x4009827a,
]);

/// Batch aggregation verification key / batch aggregation image id,
/// 957b74c4070aac8d0d0ddbae79c0082e4963af4c0e0a35c75abaa65b4c6c874c.
pub const BATCH_AGGREGATION_VK: Digest = Digest::new([
    0xc4747b95, 0x8dac0a07, 0xaedb0d0d, 0x2e08c079, 0x4caf6349, 0xc7350a0e, 0x5ba6ba5a, 0x4c876c4c,
]);

/// Batch aggregation (EVM ABI-encoded output) verification key / image id,
/// 4be0b1459541c8b1245ac28441392d5ca1667e04c23d336088af09da89ac5242.
pub const BATCH_AGGREGATION_EVM_VK: Digest = Digest::new([
    0x45b1e04b, 0xb1c84195, 0x84c25a24, 0x5c2d3941, 0x047e66a1, 0x60333dc2, 0xda09af88, 0x4252ac89,
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
                "6771d2b47a3c3f40a1a2e635b2ddf0db3159e95856879e4e8d0a665025b0026b",
            ),
            (
                "PADDING_LOGIC_VK",
                PADDING_LOGIC_VK,
                "662a8c3eccff1958d3248c9d395fb52e63597148022c69b70934f6247a820940",
            ),
            (
                "BATCH_AGGREGATION_VK",
                BATCH_AGGREGATION_VK,
                "957b74c4070aac8d0d0ddbae79c0082e4963af4c0e0a35c75abaa65b4c6c874c",
            ),
            (
                "BATCH_AGGREGATION_EVM_VK",
                BATCH_AGGREGATION_EVM_VK,
                "4be0b1459541c8b1245ac28441392d5ca1667e04c23d336088af09da89ac5242",
            ),
        ] {
            assert_eq!(konst, Digest::from_hex(hex).unwrap(), "{name} drifted");
        }
    }
}

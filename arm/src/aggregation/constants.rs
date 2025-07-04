use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Sequential aggregation proving key / sequential aggregation guest ELF binary
pub const SEQUENTIAL_AGGREGATION_PK: &[u8] =
    include_bytes!("../../elfs/sequential_aggregation.bin");
// Batch aggregation proving key / batch aggregation guest ELF binary
pub const BATCH_AGGREGATION_PK: &[u8] = include_bytes!("../../elfs/batch_aggregation.bin");

lazy_static! {
    // Sequential aggregation verification key / sequential aggregation image id.
    pub static ref SEQUENTIAL_AGGREGATION_VK: Digest =
        Digest::from_hex("4bca2e7a5569e148f6dcf933d78b3fbe52712bb7a8a0b1e2a189111a4f54c8f6").unwrap();

    // Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("a9c9a22ee9df47fd35ed2b319cd272c3f328a171ea04dab5e44ee15e33f5b9ce").unwrap();
}

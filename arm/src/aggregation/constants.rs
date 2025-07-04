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
        Digest::from_hex("78f92b519d1f6ace4d02ca5cff88653da4ad4b68d7a5022e2edda1eac6dd8805").unwrap();

    // Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("8e9d2eac78a98ec606d7082854d2582fa51bf5e36ebcf9276ea33681bfa16d5e").unwrap();
}

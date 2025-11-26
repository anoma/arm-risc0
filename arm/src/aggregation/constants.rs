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
        Digest::from_hex("1d8fee9852b3b56d5cb0f541f81ac28f5759a2b32a1d9a86af433f50e1f28375").unwrap();

    // Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("5eeeb4e5b4db4548d6c0e21c35b54041cdceda63700b060470826ee2c92740a1").unwrap();
}

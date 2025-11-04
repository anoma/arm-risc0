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
        Digest::from_hex("efcc602f5be1c3ab02e688285423ef539b45b2052581ac795967d021273a1bc7").unwrap();

    // Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("5044b1b998bbea99faf23bc096427bb1b08d74b4e38dd7f39c895ca784876706").unwrap();
}

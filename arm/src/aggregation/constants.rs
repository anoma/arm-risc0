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
        Digest::from_hex("d056773c3feeb4c64feec51e666b233002f041fa7f7611791b06740ea5d06608").unwrap();

    // Batch aggregation verification key / Batch aggregation image id.
    pub static ref BATCH_AGGREGATION_VK: Digest = Digest::from_hex("6f395f6a1c4d84a08e25982b2f775e50d61e18c18b2f44995e0ce13882d661ae").unwrap();
}

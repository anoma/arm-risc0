use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-guest.bin");

// Sequential aggregation proving key / sequential aggregation guest ELF binary
pub const SEQUENTIAL_AGGREGATION_PK: &[u8] = include_bytes!("../elfs/sequential_aggregation.bin");
// Binary tree aggregation proving key / binary tree aggregation guest ELF binary
pub const BTREE_AGGREGATION_PK: &[u8] = include_bytes!("../elfs/btree_aggregation.bin");

lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("e9f77211dc64f622255312cbe02fb883b3cf89d9a0c325f8495636e63e4cbdcb")
            .unwrap();

    // compliance verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("5e9bd5a4da94855383db7a4abb4cb1bebc733cb53362fada9deb8453f20be56d")
            .unwrap();

    // Sequential aggregation verification key / sequential aggregation image id.
    pub static ref SEQUENTIAL_AGGREGATION_VK: Digest =
        Digest::from_hex("af7bc552dba52a15b49b845f39ed2c9807b01d8ca61742e0c89624affecc30b2").unwrap();

    // Binary tree aggregation verification key / binary tree aggregation image id.
    pub static ref BTREE_AGGREGATION_VK: Digest = Digest::from_hex("ce9347cf83612f3d01a6331c6ae706fd0baecaae336fd7d8e9768edd58f6961d").unwrap();
}

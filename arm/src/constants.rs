use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance-guest.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-guest.bin");

lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("efebd91b943d5b87eef3ec2f46b7a53fdb0b4d155b17404b20c9ec7b479e229b")
            .unwrap();

    // compliance verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("89b7a43ef02c5038ba79bae8a8d61163c0437ec80c35400c65836d0a73d7798a")
            .unwrap();
}

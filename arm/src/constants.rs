use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;

// Compliance proving key / compliance guest ELF binary
pub const COMPLIANCE_PK: &[u8] = include_bytes!("../elfs/compliance_2.bin");
// Compliance var proving key / compliance guest ELF binary
pub const COMPLIANCE_VAR_PK: &[u8] = include_bytes!("../elfs/compliance_var.bin");
// Compliance sigmabus proving key / compliance guest ELF binary
pub const COMPLIANCE_SIGMABUS_PK: &[u8] = include_bytes!("../elfs/compliance_sigmabus.bin");
// Padding logic proving key / padding logic guest ELF binary
pub const PADDING_LOGIC_PK: &[u8] = include_bytes!("../elfs/trivial-logic-guest.bin");

lazy_static! {
    // compliance verification key / compliance image id
    pub static ref COMPLIANCE_VK: Digest =
        Digest::from_hex("960a69bf921f04dae43bd0337064836dba8ff52b0d9c589d20bc087af989a45c")
            .unwrap();

    // compliance_var verification key / compliance image id
    pub static ref COMPLIANCE_VAR_VK: Digest =
        Digest::from_hex("47fbde986742906d59894ee4fcf31b364869555ac534dd140bb2d5c5047323a8")
            .unwrap();

    // compliance_sigmabus verification key / compliance image id
    pub static ref COMPLIANCE_SIGMABUS_VK: Digest =
        Digest::from_hex("7e1ab7de6a233552eb0e1b3532a078eece5d159aa7a5b8f68f63a971fe6deff4")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("d67cdd850ca9eb834fb0a7ca49489d88a3301ffdd31462f502280c906bffaf75")
            .unwrap();
}

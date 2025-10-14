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
        Digest::from_hex("ff3f0fcdc1c1b5da091dd4922279a9b0ff635cc313700caa90a7097c6e59fdac")
            .unwrap();

    // compliance_var verification key / compliance image id
    pub static ref COMPLIANCE_VAR_VK: Digest =
        Digest::from_hex("ff4ba79ee21a1e8bd24cdd9c18d41e9033b5208f307b40cd1a80db62cd530b65")
            .unwrap();

    // compliance_sigmabus verification key / compliance image id
    pub static ref COMPLIANCE_SIGMABUS_VK: Digest =
        Digest::from_hex("e1770ca538a8ebcff7ba20664f8f5d069d04199f9799363747a35013c2533c38")
            .unwrap();

    // padding logic verification key / compliance image id
    pub static ref PADDING_LOGIC_VK: Digest =
        Digest::from_hex("d67cdd850ca9eb834fb0a7ca49489d88a3301ffdd31462f502280c906bffaf75")
            .unwrap();
}

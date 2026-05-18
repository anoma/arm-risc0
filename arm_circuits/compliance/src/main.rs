fn main() {}

// This is for local testing only. It updates the elf binary and prints the ID
// using the locally compiled circuit.
#[test]
fn print_compliance_elf_id() {
    use compliance_methods::{COMPLIANCE_GUEST_ELF, COMPLIANCE_GUEST_ID};
    // Write the elf binary to a file
    std::fs::write("../../arm/elfs/compliance-guest.bin", COMPLIANCE_GUEST_ELF)
        .expect("Failed to write compliance guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!(
        "COMPLIANCE_GUEST_ID: {:?}",
        Digest::from(COMPLIANCE_GUEST_ID)
    );
}

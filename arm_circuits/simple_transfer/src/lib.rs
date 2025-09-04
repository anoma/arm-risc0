// This is for local testing only. It updates the elf binary and prints the ID
// using the locally compiled circuit.
#[test]
fn print_transfer_logic_elf_id() {
    use simple_transfer_methods::{SIMPLE_TRANSFER_GUEST_ELF, SIMPLE_TRANSFER_GUEST_ID};
    // Write the elf binary to a file
    std::fs::write(
        "../../examples/simple_transfer_application/app/elf/simple-transfer-guest.bin",
        SIMPLE_TRANSFER_GUEST_ELF,
    )
    .expect("Failed to write simple transfer guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!(
        "SIMPLE_TRANSFER_GUEST_ID: {:?}",
        Digest::from(SIMPLE_TRANSFER_GUEST_ID)
    );
}

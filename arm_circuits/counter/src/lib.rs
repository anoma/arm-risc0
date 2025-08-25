// This is for local testing only. It updates the elf binary and prints the ID
// using the locally compiled circuit.
#[test]
fn print_counter_elf_id() {
    use counter_methods::{COUNTER_GUEST_ELF, COUNTER_GUEST_ID};
    // Write the elf binary to a file
    std::fs::write(
        "../../examples/simple_counter_application/app/elf/counter-guest.bin",
        COUNTER_GUEST_ELF,
    )
    .expect("Failed to write counter-guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!("COUNTER_GUEST_ID: {:?}", Digest::from(COUNTER_GUEST_ID));
}

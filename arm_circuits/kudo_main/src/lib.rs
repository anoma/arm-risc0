// This is for local testing only. It updates the elf binary and prints the ID
// using the locally compiled circuit.
#[test]
fn print_kudo_main_elf_id() {
    use kudo_main_methods::{KUDO_MAIN_GUEST_ELF, KUDO_MAIN_GUEST_ID};
    // Write the elf binary to a file
    std::fs::write(
        "../../examples/kudo_application/app/elfs/kudo-main-guest.bin",
        KUDO_MAIN_GUEST_ELF,
    )
    .expect("Failed to write kudo-main-guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!("KUDO_MAIN_GUEST_ID: {:?}", Digest::from(KUDO_MAIN_GUEST_ID));
}

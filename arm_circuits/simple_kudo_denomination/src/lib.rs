// This is for local testing only. It updates the elf binary and prints the ID
// using the locally compiled circuit.
#[test]
fn print_simple_kudo_denomination_elf_id() {
    use simple_kudo_denomination_methods::{
        SIMPLE_KUDO_DENOMINATION_GUEST_ELF, SIMPLE_KUDO_DENOMINATION_GUEST_ID,
    };
    // Write the elf binary to a file
    std::fs::write(
        "../../examples/kudo_application/app/elfs/simple-kudo-denomination-guest.bin",
        SIMPLE_KUDO_DENOMINATION_GUEST_ELF,
    )
    .expect("Failed to write simple-kudo-denomination-guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!(
        "SIMPLE_KUDO_DENOMINATION_GUEST_ID: {:?}",
        Digest::from(SIMPLE_KUDO_DENOMINATION_GUEST_ID)
    );
}

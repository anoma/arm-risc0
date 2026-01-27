pub fn main() {
    // Do nothing; this is just a placeholder main function.
}

// This is for local testing only. It updates the elf binary and prints the ID
// using the locally compiled circuit.
#[test]
fn print_aggregation_elf_id() {
    use batch_aggregation_methods::{BATCH_AGGREGATION_ELF, BATCH_AGGREGATION_ID};
    // Write the elf binary to a file
    std::fs::write(
        "../../arm/elfs/batch_aggregation.bin",
        BATCH_AGGREGATION_ELF,
    )
    .expect("Failed to write batch aggregation ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!(
        "BATCH_AGGREGATION_ID: {:?}",
        Digest::from(BATCH_AGGREGATION_ID)
    );
}

pub fn main() {
    // Do nothing; this is just a placeholder main function.
}

// This is for local testing only. It updates the elf binary and prints the ID
// using the locally compiled circuit.
#[test]
fn print_aggregation_elf_id() {
    use batch_aggregation_methods::{BATCH_AGGREGATION_GUEST_ELF, BATCH_AGGREGATION_GUEST_ID};
    #[cfg(not(feature = "abi_encoding"))]
    let elf_path = "../../arm/elfs/batch-aggregation-guest.bin";
    #[cfg(feature = "abi_encoding")]
    let elf_path = "../../arm/elfs/batch-aggregation-evm-guest.bin";
    std::fs::write(elf_path, BATCH_AGGREGATION_GUEST_ELF)
        .expect("Failed to write batch aggregation ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!(
        "BATCH_AGGREGATION_GUEST_ID: {:?}",
        Digest::from(BATCH_AGGREGATION_GUEST_ID)
    );
}

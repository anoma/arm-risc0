pub fn main() {
    // Do nothing; this is just a placeholder main function.
}

// These tests update the ELF binaries and print image IDs using the locally
// compiled circuit.  Each variant is selected by the corresponding feature flag:
//
//   default  cargo test print_aggregation_elf_id
//   borsh    cargo test --features borsh print_aggregation_borsh_elf_id
//   evm      cargo test --features evm   print_aggregation_evm_elf_id

#[cfg(not(any(feature = "borsh", feature = "evm")))]
#[test]
fn print_aggregation_elf_id() {
    use batch_aggregation_methods::{BATCH_AGGREGATION_GUEST_ELF, BATCH_AGGREGATION_GUEST_ID};

    std::fs::write(
        "../../arm/elfs/batch-aggregation-guest.bin",
        BATCH_AGGREGATION_GUEST_ELF,
    )
    .expect("Failed to write batch aggregation ELF binary");

    use risc0_zkvm::sha::Digest;
    println!(
        "BATCH_AGGREGATION_GUEST_ID: {:?}",
        Digest::from(BATCH_AGGREGATION_GUEST_ID)
    );
}

#[cfg(feature = "borsh")]
#[test]
fn print_aggregation_borsh_elf_id() {
    use batch_aggregation_methods::{BATCH_AGGREGATION_GUEST_ELF, BATCH_AGGREGATION_GUEST_ID};

    std::fs::write(
        "../../arm/elfs/batch-aggregation-borsh-guest.bin",
        BATCH_AGGREGATION_GUEST_ELF,
    )
    .expect("Failed to write batch aggregation borsh ELF binary");

    use risc0_zkvm::sha::Digest;
    println!(
        "BATCH_AGGREGATION_BORSH_GUEST_ID: {:?}",
        Digest::from(BATCH_AGGREGATION_GUEST_ID)
    );
}

#[cfg(feature = "evm")]
#[test]
fn print_aggregation_evm_elf_id() {
    use batch_aggregation_methods::{BATCH_AGGREGATION_GUEST_ELF, BATCH_AGGREGATION_GUEST_ID};

    std::fs::write(
        "../../arm/elfs/batch-aggregation-evm-guest.bin",
        BATCH_AGGREGATION_GUEST_ELF,
    )
    .expect("Failed to write batch aggregation EVM ABI ELF binary");

    use risc0_zkvm::sha::Digest;
    println!(
        "BATCH_AGGREGATION_EVM_GUEST_ID: {:?}",
        Digest::from(BATCH_AGGREGATION_GUEST_ID)
    );
}

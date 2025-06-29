use kudo_logic_circuit::{KUDO_LOGIC_ELF, KUDO_LOGIC_ID};
use kudo_logic_witness::kudo_main_witness::KudoMainWitness;
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::time::Instant;

pub fn main() {
    let witness = KudoMainWitness::default();

    let env = ExecutorEnv::builder()
        .write(&witness)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let prove_start_timer = Instant::now();
    let receipt = prover.prove(env, KUDO_LOGIC_ELF).unwrap().receipt;
    let prove_duration = prove_start_timer.elapsed();
    println!("Prove duration time: {:?}", prove_duration);

    let verify_start_timer = Instant::now();
    receipt.verify(KUDO_LOGIC_ID).unwrap();
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration);
}

#[test]
fn print_kudo_main_elf_id() {
    // Write the elf binary to a file
    std::fs::write("../elfs/kudo-main.bin", KUDO_LOGIC_ELF)
        .expect("Failed to write kudo-main guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!("Kudo-main ID: {:?}", Digest::from(KUDO_LOGIC_ID).as_bytes());
}

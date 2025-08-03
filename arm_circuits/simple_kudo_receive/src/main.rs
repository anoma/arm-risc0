use kudo_logic_witness::simple_receive_witness::SimpleReceiveLogicWitness;
use risc0_zkvm::{default_prover, ExecutorEnv};
use simple_kudo_receive_methods::{SIMPLE_KUDO_RECEIVE_GUEST_ELF, SIMPLE_KUDO_RECEIVE_GUEST_ID};
use std::time::Instant;

pub fn main() {
    let witness = SimpleReceiveLogicWitness::default();

    let env = ExecutorEnv::builder()
        .write(&witness)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let prove_start_timer = Instant::now();
    let receipt = prover
        .prove(env, SIMPLE_KUDO_RECEIVE_GUEST_ELF)
        .unwrap()
        .receipt;
    let prove_duration = prove_start_timer.elapsed();
    println!("Prove duration time: {:?}", prove_duration);

    let verify_start_timer = Instant::now();
    receipt.verify(SIMPLE_KUDO_RECEIVE_GUEST_ID).unwrap();
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration);
}

#[test]
fn print_simple_receive_elf_id() {
    // Write the elf binary to a file
    std::fs::write("../elfs/simple-receive.bin", SIMPLE_KUDO_RECEIVE_GUEST_ELF)
        .expect("Failed to write receive guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!(
        "simple-receive ID: {:?}",
        Digest::from(SIMPLE_KUDO_RECEIVE_GUEST_ID).as_bytes()
    );
}

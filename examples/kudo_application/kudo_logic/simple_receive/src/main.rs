use kudo_logic_witness::simple_receive_witness::SimpleReceiveLogicWitness;
use receive_logic_circuit::{RECEIVE_ELF, RECEIVE_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
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
    let receipt = prover.prove(env, RECEIVE_ELF).unwrap().receipt;
    let prove_duration = prove_start_timer.elapsed();
    println!("Prove duration time: {:?}", prove_duration);

    let verify_start_timer = Instant::now();
    receipt.verify(RECEIVE_ID).unwrap();
    let verify_duration = verify_start_timer.elapsed();
    println!("Verify duration time: {:?}", verify_duration);
}

#[test]
fn print_simple_receive_elf_id() {
    // Write the elf binary to a file
    std::fs::write("../elfs/simple-receive.bin", RECEIVE_ELF)
        .expect("Failed to write receive guest ELF binary");

    // Print the ID
    use risc0_zkvm::sha::Digest;
    println!(
        "simple-receive ID: {:?}",
        Digest::from(RECEIVE_ID).as_bytes()
    );
}

use fibonacci_risc0_methods::{FIBONACCI_RISC0_GUEST_ELF, FIBONACCI_RISC0_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::time::Instant;

fn main() {
    let n: u32 = 50;

    let env = ExecutorEnv::builder()
        .write(&n)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    println!("Proving fib({n})...");
    let start = Instant::now();
    let prove_info = prover.prove(env, FIBONACCI_RISC0_GUEST_ELF).unwrap();
    let prove_duration = start.elapsed();

    let receipt = prove_info.receipt;
    let output: u128 = receipt.journal.decode().unwrap();
    println!("fib({n}) = {output}");
    println!("Prove time: {:?}", prove_duration);

    println!("Verifying...");
    let start = Instant::now();
    receipt.verify(FIBONACCI_RISC0_GUEST_ID).unwrap();
    let verify_duration = start.elapsed();
    println!("Verify time: {:?}", verify_duration);
}

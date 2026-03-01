use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use sha2_bench_methods::{SHA2_BENCH_GUEST_ELF, SHA2_BENCH_GUEST_ID};
use std::time::Instant;

fn main() {
    for &count in &[10u32, 100, 1000, 10000] {
        println!("\n=== Benchmarking {} SHA-256 hashes ===", count);

        let env = ExecutorEnv::builder()
            .write(&count)
            .unwrap()
            .build()
            .unwrap();

        let prover = default_prover();

        let prove_start = Instant::now();

        let prove_info = prover
            .prove_with_ctx(
                env,
                &VerifierContext::default(),
                SHA2_BENCH_GUEST_ELF,
                &ProverOpts::succinct(),
            )
            .unwrap();

        let receipt = prove_info.receipt;
        let prove_duration = prove_start.elapsed();

        println!("  Prove duration:   {:?}", prove_duration);
        println!("  Total cycles:     {}", prove_info.stats.total_cycles);
        println!("  User cycles:      {}", prove_info.stats.user_cycles);

        let verify_start = Instant::now();
        receipt.verify(SHA2_BENCH_GUEST_ID).unwrap();
        let verify_duration = verify_start.elapsed();

        println!("  Verify duration:  {:?}", verify_duration);
    }
}

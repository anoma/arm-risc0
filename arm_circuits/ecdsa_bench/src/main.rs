use ecdsa_bench_methods::{ECDSA_BENCH_GUEST_ELF, ECDSA_BENCH_GUEST_ID};
use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use std::time::Instant;

fn main() {
    // Fixed signing key for reproducibility
    let sk_bytes = [1u8; 32];
    let signing_key = SigningKey::from_slice(&sk_bytes).unwrap();
    let vk_bytes: Vec<u8> = signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    for &count in &[1u32, 10] {
        println!("\n=== Benchmarking {} ECDSA-secp256k1 verifications ===", count);

        // Generate count distinct (signature, message) pairs
        let items: Vec<(Vec<u8>, [u8; 32])> = (0..count)
            .map(|i| {
                let msg = [i as u8; 32];
                let sig: Signature = signing_key.sign(&msg);
                let sig_bytes: Vec<u8> = sig.to_bytes().to_vec();
                (sig_bytes, msg)
            })
            .collect();

        let env = ExecutorEnv::builder()
            .write(&vk_bytes)
            .unwrap()
            .write(&items)
            .unwrap()
            .build()
            .unwrap();

        let prover = default_prover();

        let prove_start = Instant::now();

        let prove_info = prover
            .prove_with_ctx(
                env,
                &VerifierContext::default(),
                ECDSA_BENCH_GUEST_ELF,
                &ProverOpts::succinct(),
            )
            .unwrap();

        let receipt = prove_info.receipt;
        let prove_duration = prove_start.elapsed();

        println!("  Prove duration:   {:?}", prove_duration);
        println!("  Total cycles:     {}", prove_info.stats.total_cycles);
        println!("  User cycles:      {}", prove_info.stats.user_cycles);

        let verify_start = Instant::now();
        receipt.verify(ECDSA_BENCH_GUEST_ID).unwrap();
        let verify_duration = verify_start.elapsed();

        println!("  Verify duration:  {:?}", verify_duration);
    }
}

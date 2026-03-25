#[cfg(feature = "prove")]
use anoma_rm_risc0::execution_proof::ExecutionProofWitness;

pub fn main() {
    // Do nothing; this is just a placeholder main function.
}

/// Builds an ExecutorEnv with all inner receipts from the witness added as
/// assumptions, then proves the execution circuit.
#[cfg(feature = "prove")]
pub fn prove(
    witness: &ExecutionProofWitness,
    proof_type: risc0_zkvm::ProverOpts,
) -> Result<risc0_zkvm::Receipt, Box<dyn std::error::Error>> {
    use execution_proof_methods::EXECUTION_PROOF_GUEST_ELF;
    use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, VerifierContext};

    let mut env_builder = ExecutorEnv::builder();

    for tx in &witness.transactions {
        if let Some(agg_bytes) = &tx.aggregation_proof {
            // Add the aggregation inner receipt as an assumption.
            let inner: InnerReceipt = bincode::deserialize(agg_bytes)?;
            env_builder.add_assumption(inner);
        } else {
            // Add individual compliance and logic inner receipts as assumptions.
            for inner in tx.get_compliance_inner_receipts()? {
                env_builder.add_assumption(inner);
            }
            for inner in tx.get_logic_inner_receipts()? {
                env_builder.add_assumption(inner);
            }
        }
    }

    let env = env_builder.write(witness)?.build()?;

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            EXECUTION_PROOF_GUEST_ELF,
            &proof_type,
        )?
        .receipt;

    Ok(receipt)
}

// Updates the ELF binary and prints the image ID.
// Run with: cargo test --features prove print_execution_proof_elf_id -- --nocapture
#[test]
fn print_execution_proof_elf_id() {
    use execution_proof_methods::{EXECUTION_PROOF_GUEST_ELF, EXECUTION_PROOF_GUEST_ID};

    std::fs::write(
        "../../arm/elfs/execution-proof-guest.bin",
        EXECUTION_PROOF_GUEST_ELF,
    )
    .expect("Failed to write execution proof guest ELF binary");

    use risc0_zkvm::sha::Digest;
    println!(
        "EXECUTION_PROOF_GUEST_ID: {:?}",
        Digest::from(EXECUTION_PROOF_GUEST_ID)
    );
}

/// Verifies a proved execution receipt against the expected image ID.
#[cfg(feature = "prove")]
pub fn verify(receipt: &risc0_zkvm::Receipt) -> Result<(), Box<dyn std::error::Error>> {
    use execution_proof_methods::EXECUTION_PROOF_GUEST_ID;
    receipt.verify(EXECUTION_PROOF_GUEST_ID)?;
    Ok(())
}

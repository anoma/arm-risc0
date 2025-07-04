use risc0_zkvm::{default_prover, Digest, ExecutorEnv, Receipt, VerifierContext};
use risc0_zkvm::{InnerReceipt, ProverOpts};
use serde::{Deserialize, Serialize};

use crate::aggregation::{
    constants::{BATCH_AGGREGATION_PK, BATCH_AGGREGATION_VK},
    BatchCU, BatchLP,
};
use crate::constants::COMPLIANCE_VK;
use crate::transaction::Transaction;
use crate::utils::words_to_bytes;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProof(pub InnerReceipt);

/// Aggregates base proofs in batches.
pub struct BatchAggregation;

impl BatchAggregation {
    pub fn prove_transaction_aggregation(tx: &Transaction) -> Option<BatchProof> {
        // Collect instances, proofs, and keys.
        let BatchCU {
            instances: cu_instances,
            receipts: cu_receipts,
        } = tx.clone().into();

        let batch_lp: Result<BatchLP, _> = tx.clone().try_into();
        let BatchLP {
            instances: lp_instances,
            keys: lp_keys,
            receipts: lp_receipts,
        } = batch_lp.ok()?;

        let mut env_builder = ExecutorEnv::builder();

        // Add proofs as assumptions.
        for receipt in cu_receipts?.into_iter().chain(lp_receipts?.into_iter()) {
            env_builder.add_assumption(receipt);
        }
        // Write instances and keys to guest input.
        let compliance_key: Digest = *COMPLIANCE_VK;
        let env = env_builder
            .write(&cu_instances)
            .unwrap()
            .write(&compliance_key)
            .unwrap()
            .write(&lp_instances)
            .unwrap()
            .write(&lp_keys)
            .unwrap()
            .build()
            .unwrap();

        #[cfg(feature = "fast_aggregation")]
        let prover_opts = ProverOpts::fast();

        #[cfg(all(not(feature = "fast_aggregation"), feature = "groth16_aggregation"))]
        let prover_opts = ProverOpts::groth16();

        #[cfg(all(
            not(feature = "fast_aggregation"),
            not(feature = "groth16_aggregation")
        ))]
        let prover_opts = ProverOpts::succinct();

        let prover = default_prover();

        // Prove batch.
        let receipt = prover.prove_with_ctx(
            env,
            &VerifierContext::default(),
            BATCH_AGGREGATION_PK,
            &prover_opts,
        );

        match receipt {
            Ok(pi) => Some(BatchProof(pi.receipt.inner)),
            Err(_) => None,
        }
    }

    pub fn verify_transaction_aggregation(tx: &Transaction, proof: &BatchProof) -> Option<()> {
        // Form the batch instance.
        let BatchCU {
            instances: compliance_instances,
            receipts: _,
        } = tx.clone().into();
        let BatchLP {
            instances: logic_instances,
            keys: logic_keys,
            receipts: _,
        } = tx.clone().try_into().ok()?;

        let batch_instance = risc0_zkvm::serde::to_vec(&(
            compliance_instances,
            *COMPLIANCE_VK,
            logic_instances,
            logic_keys,
        ))
        .ok()?;

        // Verify proof on the batch instance.
        let receipt = Receipt::new(proof.0.clone(), words_to_bytes(&batch_instance).to_vec());

        receipt.verify(*BATCH_AGGREGATION_VK).ok()
    }
}

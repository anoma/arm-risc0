use risc0_zkvm::{default_prover, Digest, ExecutorEnv, Receipt, VerifierContext};
use risc0_zkvm::{InnerReceipt, ProverOpts};
use serde::{Deserialize, Serialize};

use crate::aggregation::{
    constants::{BATCH_AGGREGATION_PK, BATCH_AGGREGATION_VK},
    BatchCU, BatchLP,
};
use crate::compliance::ComplianceInstanceWords;
use crate::constants::COMPLIANCE_VK;
use crate::error::ArmError;
use crate::transaction::Transaction;
use crate::utils::{bytes_to_words, words_to_bytes};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProof(pub InnerReceipt);

/// Aggregates base proofs in batches.
pub struct BatchAggregation;

impl BatchAggregation {
    pub fn prove_transaction_aggregation(tx: &Transaction) -> Result<BatchProof, ArmError> {
        // Collect instances, proofs, and keys.
        let BatchCU {
            instances: cu_instances,
            receipts: cu_receipts,
        } = tx.get_batch_cu();

        let BatchLP {
            instances: lp_instances,
            keys: lp_keys,
            receipts: lp_receipts,
        } = tx.get_batch_lp()?;

        let mut cu_instances_u32: Vec<ComplianceInstanceWords> = Vec::new();
        for ci in cu_instances.iter() {
            cu_instances_u32.push(ComplianceInstanceWords {
                u32_words: bytes_to_words(ci).try_into().map_err(|_| {
                    ArmError::ProveFailed(
                        "Error converting compliance instance into fixed-size u32 words".into(),
                    )
                })?,
            });
        }
        let lp_instances_u32: Vec<Vec<u32>> = lp_instances
            .iter()
            .map(|bytes| bytes_to_words(bytes))
            .collect();

        let mut env_builder = ExecutorEnv::builder();

        // Add proofs as assumptions
        if let (Some(cu_receipts), Some(lp_receipts)) = (cu_receipts, lp_receipts) {
            for receipt in cu_receipts.into_iter().chain(lp_receipts.into_iter()) {
                env_builder.add_assumption(receipt);
            }
        } else {
            return Err(ArmError::ProofVerificationFailed(
                "Cannot aggregate: missing individual proof(s)".into(),
            ));
        }

        // Write instances and keys to guest input.
        let compliance_key: Digest = *COMPLIANCE_VK;
        let env = env_builder
            .write(&cu_instances_u32)
            .map_err(|_| ArmError::WriteWitnessFailed)?
            .write(&compliance_key)
            .map_err(|_| ArmError::WriteWitnessFailed)?
            .write(&lp_instances_u32)
            .map_err(|_| ArmError::WriteWitnessFailed)?
            .write(&lp_keys)
            .map_err(|_| ArmError::WriteWitnessFailed)?
            .build()
            .map_err(|_| ArmError::BuildProverEnvFailed)?;

        #[cfg(feature = "groth16_aggregation")]
        let prover_opts = ProverOpts::groth16();

        #[cfg(not(feature = "groth16_aggregation"))]
        let prover_opts = ProverOpts::succinct();

        let prover = default_prover();

        // Prove batch.
        let receipt = prover
            .prove_with_ctx(
                env,
                &VerifierContext::default(),
                BATCH_AGGREGATION_PK,
                &prover_opts,
            )
            .map_err(|err| ArmError::ProveFailed(format!("Proof generation failed: {}", err)))?
            .receipt;

        Ok(BatchProof(receipt.inner))
    }

    pub fn verify_transaction_aggregation(
        tx: &Transaction,
        proof: &BatchProof,
    ) -> Result<(), ArmError> {
        // Form the batch instance.
        let BatchCU {
            instances: compliance_instances,
            receipts: _,
        } = tx.get_batch_cu();
        let BatchLP {
            instances: logic_instances,
            keys: logic_keys,
            receipts: _,
        } = tx.get_batch_lp()?;

        let mut compliance_instances_u32: Vec<ComplianceInstanceWords> = Vec::new();
        for ci in compliance_instances.iter() {
            compliance_instances_u32.push(ComplianceInstanceWords {
                u32_words: bytes_to_words(ci).try_into().map_err(|_| {
                    ArmError::ProofVerificationFailed(
                        "Error converting compliance instance into fixed-size u32 words".into(),
                    )
                })?,
            });
        }
        let logic_instances_u32: Vec<Vec<u32>> = logic_instances
            .iter()
            .map(|bytes| bytes_to_words(bytes))
            .collect();

        let batch_instance = risc0_zkvm::serde::to_vec(&(
            compliance_instances_u32,
            *COMPLIANCE_VK,
            logic_instances_u32,
            logic_keys,
        ))
        .map_err(|_| ArmError::InstanceSerializationFailed)?;

        // Verify proof on the batch instance.
        let receipt = Receipt::new(proof.0.clone(), words_to_bytes(&batch_instance).to_vec());

        receipt.verify(*BATCH_AGGREGATION_VK).map_err(|err| {
            ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
        })
    }
}

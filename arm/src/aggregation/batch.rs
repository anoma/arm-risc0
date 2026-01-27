//! Aggregation of base proofs into batch proofs.

use risc0_zkvm::{default_prover, Digest, ExecutorEnv, Receipt, VerifierContext};
use risc0_zkvm::{InnerReceipt, ProverOpts};

use crate::aggregation::constants::{BATCH_AGGREGATION_PK, BATCH_AGGREGATION_VK};
use crate::compliance::ComplianceInstanceWords;
use crate::constants::COMPLIANCE_VK;
use crate::error::ArmError;
use crate::proving_system::ProofType;
use crate::transaction::Transaction;
use crate::utils::{bytes_to_words, words_to_bytes};

/// Proves the aggregation of a transaction's base proofs into a batch proof.
pub fn prove_transaction_aggregation(
    tx: &Transaction,
    proof_type: ProofType,
) -> Result<InnerReceipt, ArmError> {
    // Check base proofs exist.
    if tx.base_proofs_are_empty() {
        return Err(ArmError::ProveFailed(
            "Cannot aggregate: missing individual proof(s)".into(),
        ));
    }

    // Collect compliance inner_receipts/proofs and instances.
    let compliance_units = tx.get_compliance_units();
    let compliance_inner_receipts = compliance_units
        .iter()
        .map(|cu| cu.get_inner_receipt())
        .collect::<Result<Vec<InnerReceipt>, ArmError>>()?;
    let compliance_instances_u32: Vec<ComplianceInstanceWords> = compliance_units
        .iter()
        .map(|cu| {
            Ok(ComplianceInstanceWords {
                u32_words: bytes_to_words(&cu.instance).try_into().map_err(|_| {
                    ArmError::ProveFailed(
                        "Error converting compliance instance into fixed-size u32 words".into(),
                    )
                })?,
            })
        })
        .collect::<Result<Vec<ComplianceInstanceWords>, ArmError>>()?;

    // Collect logic inner_receipts/proofs, vks, and instances.
    let logic_verifiers = tx.get_logic_verifiers()?;
    let logic_inner_receipts = logic_verifiers
        .iter()
        .map(|lp| lp.get_inner_receipt())
        .collect::<Result<Vec<InnerReceipt>, ArmError>>()?;
    let lp_keys: Vec<Digest> = logic_verifiers.iter().map(|lp| lp.verifying_key).collect();
    let lp_instances_u32: Vec<Vec<u32>> = logic_verifiers
        .iter()
        .map(|lp| bytes_to_words(&lp.instance))
        .collect();

    // Add proofs as assumptions
    let mut env_builder = ExecutorEnv::builder();
    for inner_receipt in compliance_inner_receipts
        .into_iter()
        .chain(logic_inner_receipts.into_iter())
    {
        env_builder.add_assumption(inner_receipt);
    }

    // Write instances and keys to guest input.
    let compliance_key: Digest = *COMPLIANCE_VK;
    let env = env_builder
        .write(&compliance_instances_u32)
        .map_err(|_| ArmError::WriteWitnessFailed)?
        .write(&compliance_key)
        .map_err(|_| ArmError::WriteWitnessFailed)?
        .write(&lp_instances_u32)
        .map_err(|_| ArmError::WriteWitnessFailed)?
        .write(&lp_keys)
        .map_err(|_| ArmError::WriteWitnessFailed)?
        .build()
        .map_err(|_| ArmError::BuildProverEnvFailed)?;

    let prover_opts = match proof_type {
        ProofType::Succinct => {
            ProverOpts::succinct() // Succinct receipts, constant size.
        }
        ProofType::Groth16 => {
            ProverOpts::groth16() // Groth16 receipts, constant size, blockchain-friendly.
        }
    };

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

    Ok(receipt.inner)
}

/// Verifies the aggregated batch proof of a transaction.
pub fn verify_transaction_aggregation(tx: &Transaction) -> Result<(), ArmError> {
    if let Some(proof) = &tx.aggregation_proof {
        let compliance_instances_u32 = tx
            .get_compliance_units()
            .iter()
            .map(|cu| {
                Ok(ComplianceInstanceWords {
                    u32_words: bytes_to_words(&cu.instance).try_into().map_err(|_| {
                        ArmError::ProofVerificationFailed(
                            "Error converting compliance instance into fixed-size u32 words".into(),
                        )
                    })?,
                })
            })
            .collect::<Result<Vec<ComplianceInstanceWords>, ArmError>>()?;

        // Collect logic inner_receipts/proofs, vks, and instances.
        let logic_verifiers = tx.get_logic_verifiers()?;
        let logic_keys: Vec<Digest> = logic_verifiers.iter().map(|lp| lp.verifying_key).collect();
        let logic_instances_u32: Vec<Vec<u32>> = logic_verifiers
            .iter()
            .map(|lp| bytes_to_words(&lp.instance))
            .collect();

        let batch_instance = risc0_zkvm::serde::to_vec(&(
            compliance_instances_u32,
            *COMPLIANCE_VK,
            logic_instances_u32,
            logic_keys,
        ))
        .map_err(|_| ArmError::InstanceSerializationFailed)?;

        let inner_receipt: InnerReceipt =
            bincode::deserialize(proof).map_err(|_| ArmError::InnerReceiptDeserializationError)?;

        // Verify proof on the batch instance.
        let receipt = Receipt::new(inner_receipt, words_to_bytes(&batch_instance).to_vec());

        receipt.verify(*BATCH_AGGREGATION_VK).map_err(|err| {
            ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
        })
    } else {
        Err(ArmError::ProofVerificationFailed(
            "Missing aggregation proof".into(),
        ))
    }
}

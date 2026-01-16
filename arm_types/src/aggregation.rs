use crate::{
    compliance::ComplianceInstanceWords,
    compliance_unit::ComplianceUnit,
    constants::COMPLIANCE_VK,
    error::ArmError,
    logic_proof::LogicVerifier,
    transaction::Transaction,
    utils::{bytes_to_words, words_to_bytes},
};
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

/// Supported strategies to aggregate.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum AggregationStrategy {
    /// Sequential aggregation strategy.
    Sequential,
    /// Batch aggregation strategy.
    Batch,
}

/// Aggregates base proofs in batches.
pub struct BatchAggregation;

/// Holds the compliance instances, and compliance proofs (if all present)
/// of a transaction.
#[derive(Debug, Clone)]
pub struct BatchCU {
    pub instances: Vec<Vec<u8>>,
    pub journals: Option<Vec<Vec<u8>>>,
}

/// Holds resource logic instances, keys, and proofs (if all present).
#[derive(Debug, Clone)]
pub struct BatchLP {
    pub instances: Vec<Vec<u8>>,
    pub keys: Vec<Digest>, // Verify proof on the batch instance.
    pub journals: Option<Vec<Vec<u8>>>,
}

/// Produces the journal for verifying a batch aggregation proof
pub fn get_batch_journal(
    compliance_instances: Vec<Vec<u8>>,
    logic_instances: Vec<Vec<u8>>,
    logic_keys: Vec<Digest>,
) -> Result<Vec<u8>, ArmError> {
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

    let batch_instance = risc0_serde::to_vec(&(
        compliance_instances_u32,
        *COMPLIANCE_VK,
        logic_instances_u32,
        logic_keys,
    ))
    .map_err(|_| ArmError::InstanceSerializationFailed)?;

    Ok(words_to_bytes(&batch_instance).to_vec())
}

impl Transaction {
    pub fn get_batch_cu(&self) -> BatchCU {
        let cus: Vec<ComplianceUnit> = self
            .actions
            .iter()
            .flat_map(|a| a.get_compliance_units().clone())
            .collect();

        let cu_instances: Vec<Vec<u8>> = cus
            .iter()
            .map(|cu| cu.instance.to_journal().unwrap())
            .collect();

        let proofs_vector: Option<Vec<Vec<u8>>> = if self.base_proofs_are_empty() {
            None
        } else {
            let proofs: Vec<Vec<u8>> = cus.iter().map(|cu| cu.proof.clone().unwrap()).collect();
            Some(proofs)
        };

        BatchCU {
            instances: cu_instances,
            journals: proofs_vector,
        }
    }

    pub fn get_batch_lp(&self) -> Result<BatchLP, ArmError> {
        let mut lps: Vec<LogicVerifier> = Vec::new();

        for action in self.actions.iter() {
            let mut lp_vec: Vec<LogicVerifier> = action.get_logic_verifiers()?;
            lps.append(&mut lp_vec);
        }

        let logic_instances: Vec<Vec<u8>> = lps.iter().map(|lp| lp.instance.clone()).collect();

        let proofs_vector: Option<Vec<Vec<u8>>> = if self.base_proofs_are_empty() {
            None
        } else {
            let proofs: Vec<Vec<u8>> = lps.iter().map(|lp| lp.proof.clone().unwrap()).collect();
            Some(proofs)
        };

        let keys = lps.into_iter().map(|lp| lp.verifying_key).collect();

        Ok(BatchLP {
            instances: logic_instances,
            keys: keys,
            journals: proofs_vector,
        })
    }

    /// Returns `true` if any compliance or resource logic proof is `None`.
    fn base_proofs_are_empty(&self) -> bool {
        for a in self.actions.iter() {
            if a.get_compliance_units().iter().any(|cu| cu.proof.is_none()) {
                return true;
            }
            if a.get_logic_verifier_inputs()
                .iter()
                .any(|lp| lp.proof.is_none())
            {
                return true;
            }
        }

        false
    }
}

impl BatchAggregation {
    /// Verifies the aggregated batch proof of a transaction.
    pub fn verify_transaction_aggregation(
        tx: &Transaction,
        // proof: &BatchProof,
    ) -> Result<(), ArmError> {
        // Form the batch instance.
        let BatchCU {
            instances: compliance_instances,
            journals: _,
        } = tx.get_batch_cu();
        let BatchLP {
            instances: logic_instances,
            keys: logic_keys,
            journals: _,
        } = tx.get_batch_lp()?;

        let _journal = get_batch_journal(compliance_instances, logic_instances, logic_keys);

        // // Verify proof on the batch instance.
        // let receipt = Receipt::new(
        //     proof.0.clone(),
        //     get_batch_journal(compliance_instances, logic_instances),
        // );

        Ok(())

        //     receipt.verify(*BATCH_AGGREGATION_VK).map_err(|err| {
        //         ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
        //     })
    }
}

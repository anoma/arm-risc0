//! Transaction extensions and associated methods.

pub use arm_core::transaction::{Delta, Transaction};

use arm_core::delta_types::{DeltaProof as CoreDeltaProof, DeltaWitness as CoreDeltaWitness};
use risc0_zkvm::InnerReceipt;

#[cfg(feature = "aggregation")]
use crate::{
    constants::{BATCH_AGGREGATION_PK, BATCH_AGGREGATION_VK, COMPLIANCE_VK},
    proving_system::ProofType,
    utils::{bytes_to_words, core_to_risc0_digest, words_to_bytes},
    ComplianceInstanceWords,
};
#[cfg(feature = "aggregation")]
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext};

use crate::{
    action::ActionExt,
    compliance::ComplianceInstanceJournalExt,
    compliance_unit::ComplianceUnitExt,
    delta_proof::{DeltaInstance, DeltaProof, DeltaWitness},
    error::ArmError,
    logic_proof::{LogicVerifier, LogicVerifierInputsExt},
    Digest,
};

/// Extension methods for transactions that require zkvm/k256 functionality.
pub trait TransactionExt {
    /// Generates the delta proof for the transaction if it contains a delta witness.
    fn generate_delta_proof(self) -> Result<Transaction, ArmError>;

    /// Verifies all the proofs and corresponding checks in the transaction.
    fn verify(&self) -> Result<(), ArmError>;

    /// Returns the DeltaInstance constructed from the sum of all actions' deltas.
    fn delta(&self) -> Result<DeltaInstance, ArmError>;

    /// Composes two transactions by concatenating their actions and combining their delta witnesses.
    fn compose(tx1: Transaction, tx2: Transaction) -> Transaction
    where
        Self: Sized;

    /// Returns all compliance inner receipts in the transaction.
    fn get_compliance_inner_receipts(&self) -> Result<Vec<InnerReceipt>, ArmError>;

    /// Returns all logic inner receipts in the transaction.
    fn get_logic_inner_receipts(&self) -> Result<Vec<InnerReceipt>, ArmError>;

    /// Returns all compliance instances in serialized journal format.
    fn get_compliance_instances(&self) -> Result<Vec<Vec<u8>>, ArmError>;

    /// Returns all logic verifiers in the transaction.
    fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError>;

    /// Returns all logic verifying keys and instances in the transaction.
    fn get_logic_vks_and_instances(&self) -> Result<(Vec<Digest>, Vec<Vec<u8>>), ArmError>;

    /// Aggregates all the transaction proofs.
    #[cfg(feature = "aggregation")]
    fn aggregate(&mut self, proof_type: ProofType) -> Result<(), ArmError>;

    /// Verifies the aggregated proof of the transaction.
    #[cfg(feature = "aggregation")]
    fn verify_aggregation(&self) -> Result<(), ArmError>;

    /// Constructs the aggregation instance by serializing all compliance and logic instances.
    #[cfg(feature = "aggregation")]
    fn construct_aggregation_instance(&self) -> Result<Vec<u8>, ArmError>;
}

impl TransactionExt for Transaction {
    fn generate_delta_proof(self) -> Result<Transaction, ArmError> {
        match self.delta_proof {
            Delta::Witness(ref witness) => {
                let witness = DeltaWitness::from_bytes(&witness.0)?;
                let msg = self.get_delta_msg();
                let proof = DeltaProof::prove(&msg, &witness)?;
                let delta_proof = Delta::Proof(CoreDeltaProof(proof.to_bytes()));
                Ok(Transaction {
                    actions: self.actions,
                    delta_proof,
                    expected_balance: self.expected_balance,
                    aggregation_proof: self.aggregation_proof,
                })
            }
            Delta::Proof(_) => Ok(self),
        }
    }

    fn verify(&self) -> Result<(), ArmError> {
        match &self.delta_proof {
            Delta::Proof(proof) => {
                let proof = DeltaProof::from_bytes(&proof.0)?;
                let msg = self.get_delta_msg();
                let instance = self.delta()?;
                DeltaProof::verify(&msg, &proof, instance)?;

                // Check for nullifier duplication across all compliance units.
                self.nf_duplication_check()?;

                if self.aggregation_proof.is_some() {
                    #[cfg(not(feature = "aggregation"))]
                    return Err(ArmError::ProofVerificationFailed(
                        "feature `aggregation` is not enabled".into(),
                    ));

                    #[cfg(feature = "aggregation")]
                    self.verify_aggregation()?;
                } else {
                    // Try verifying individually.
                    for action in self.actions.iter() {
                        action.verify()?;
                    }
                }
                Ok(())
            }
            Delta::Witness(_) => Err(ArmError::ExpectedDeltaProof),
        }
    }

    fn delta(&self) -> Result<DeltaInstance, ArmError> {
        let mut points = Vec::with_capacity(self.actions.len());
        for action in &self.actions {
            points.push(action.delta()?);
        }
        DeltaInstance::from_deltas(&points)
    }

    fn compose(tx1: Transaction, tx2: Transaction) -> Transaction {
        let mut actions = tx1.actions;
        actions.extend(tx2.actions);
        let delta = match (&tx1.delta_proof, &tx2.delta_proof) {
            (Delta::Witness(witness1), Delta::Witness(witness2)) => {
                let witness1 = DeltaWitness::from_bytes(&witness1.0)
                    .expect("invalid witness bytes in first transaction");
                let witness2 = DeltaWitness::from_bytes(&witness2.0)
                    .expect("invalid witness bytes in second transaction");
                let composed = witness1.compose(&witness2);
                Delta::Witness(CoreDeltaWitness(composed.to_bytes()))
            }
            _ => panic!("Cannot compose transactions with different delta types"),
        };
        Transaction::create(actions, delta)
    }

    fn get_compliance_inner_receipts(&self) -> Result<Vec<InnerReceipt>, ArmError> {
        let mut compliance_inner_receipts = Vec::new();
        for cu in self.get_compliance_units() {
            let inner_receipt = cu.get_inner_receipt()?;
            compliance_inner_receipts.push(inner_receipt);
        }
        Ok(compliance_inner_receipts)
    }

    fn get_logic_inner_receipts(&self) -> Result<Vec<InnerReceipt>, ArmError> {
        let mut logic_inner_receipts = Vec::new();
        for action in &self.actions {
            let logic_inputs = action.get_logic_verifier_inputs();
            for lp in logic_inputs {
                let inner_receipt = lp.get_inner_receipt()?;
                logic_inner_receipts.push(inner_receipt);
            }
        }
        Ok(logic_inner_receipts)
    }

    fn get_compliance_instances(&self) -> Result<Vec<Vec<u8>>, ArmError> {
        let mut result = Vec::new();
        for cu in self.get_compliance_units() {
            result.push(cu.instance.to_journal()?);
        }
        Ok(result)
    }

    fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError> {
        let mut result = Vec::new();
        for action in &self.actions {
            let logic_verifiers = action.get_logic_verifiers()?;
            result.extend(logic_verifiers);
        }
        Ok(result)
    }

    fn get_logic_vks_and_instances(&self) -> Result<(Vec<Digest>, Vec<Vec<u8>>), ArmError> {
        let mut vks = Vec::new();
        let mut instances = Vec::new();
        for lp in self.get_logic_verifiers()? {
            vks.push(lp.verifying_key);
            instances.push(lp.instance.clone());
        }
        Ok((vks, instances))
    }

    #[cfg(feature = "aggregation")]
    fn aggregate(&mut self, proof_type: ProofType) -> Result<(), ArmError> {
        // Check base proofs exist.
        if self.base_proofs_are_empty() {
            return Err(ArmError::ProveFailed(
                "Cannot aggregate: missing individual proof(s)".into(),
            ));
        }

        // Collect inner_receipts/proofs and instances.
        let compliance_inner_receipts = self.get_compliance_inner_receipts()?;
        let logic_inner_receipts = self.get_logic_inner_receipts()?;
        let compliance_instances_u32: Vec<ComplianceInstanceWords> = self
            .get_compliance_instances()?
            .iter()
            .map(|instance_bytes| ComplianceInstanceWords::from_bytes(instance_bytes))
            .collect::<Result<Vec<ComplianceInstanceWords>, ArmError>>()?;

        let (lp_vks, lp_instances) = self.get_logic_vks_and_instances()?;
        let lp_instances_u32: Vec<Vec<u32>> = lp_instances
            .iter()
            .map(|instance_bytes| bytes_to_words(instance_bytes))
            .collect();

        // Add proofs as assumptions.
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
            .write(&lp_vks)
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
        let agg_proof = prover
            .prove_with_ctx(
                env,
                &VerifierContext::default(),
                BATCH_AGGREGATION_PK,
                &prover_opts,
            )
            .map_err(|err| ArmError::ProveFailed(format!("Proof generation failed: {}", err)))?
            .receipt
            .inner;

        self.aggregation_proof =
            Some(bincode::serialize(&agg_proof).map_err(|_| ArmError::SerializationError)?);

        erase_base_proofs(self);
        Ok(())
    }

    #[cfg(feature = "aggregation")]
    fn verify_aggregation(&self) -> Result<(), ArmError> {
        if let Some(proof) = &self.aggregation_proof {
            let instance = self.construct_aggregation_instance()?;

            let inner_receipt: InnerReceipt = bincode::deserialize(proof)
                .map_err(|_| ArmError::InnerReceiptDeserializationError)?;

            // Verify proof on the batch instance.
            let receipt = Receipt::new(inner_receipt, instance);
            let batch_vk = core_to_risc0_digest(&BATCH_AGGREGATION_VK);

            receipt.verify(batch_vk).map_err(|err| {
                ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
            })
        } else {
            Err(ArmError::ProofVerificationFailed(
                "Missing aggregation proof".into(),
            ))
        }
    }

    #[cfg(feature = "aggregation")]
    fn construct_aggregation_instance(&self) -> Result<Vec<u8>, ArmError> {
        let compliance_instances_u32: Vec<ComplianceInstanceWords> = self
            .get_compliance_instances()?
            .iter()
            .map(|instance_bytes| ComplianceInstanceWords::from_bytes(instance_bytes))
            .collect::<Result<Vec<ComplianceInstanceWords>, ArmError>>()?;

        let (lp_vks, lp_instances) = self.get_logic_vks_and_instances()?;
        let lp_instances_u32: Vec<Vec<u32>> = lp_instances
            .iter()
            .map(|instance_bytes| bytes_to_words(instance_bytes))
            .collect();

        let instance = risc0_zkvm::serde::to_vec(&(
            compliance_instances_u32,
            *COMPLIANCE_VK,
            lp_instances_u32,
            lp_vks,
        ))
        .map_err(|_| ArmError::InstanceSerializationFailed)?;

        Ok(words_to_bytes(&instance).to_vec())
    }
}

#[cfg(feature = "aggregation")]
fn erase_base_proofs(tx: &mut Transaction) {
    for a in &mut tx.actions {
        for cu in &mut a.compliance_units {
            cu.proof = None;
        }
        for lp in &mut a.logic_verifier_inputs {
            lp.proof = None;
        }
    }
}

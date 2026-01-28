//! Transaction structure and associated methods.

#[cfg(feature = "aggregation")]
use crate::{
    compliance::ComplianceInstanceWords,
    constants::{BATCH_AGGREGATION_PK, BATCH_AGGREGATION_VK, COMPLIANCE_VK},
    proving_system::ProofType,
    utils::{bytes_to_words, words_to_bytes},
};
#[cfg(feature = "aggregation")]
use risc0_zkvm::{
    default_prover, Digest, ExecutorEnv, InnerReceipt, ProverOpts, Receipt, VerifierContext,
};

use crate::{
    action::Action,
    compliance_unit::ComplianceUnit,
    delta_proof::{DeltaInstance, DeltaProof, DeltaWitness},
    error::ArmError,
    logic_proof::LogicVerifier,
};
use serde::{Deserialize, Serialize};

/// Represents a transaction consisting of actions, delta proof, expected balance,
/// and optional aggregation proof.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Transaction {
    /// The actions included in the transaction.
    pub actions: Vec<Action>,
    /// The delta proof, which can be either a witness for proving or a proof for verification.
    pub delta_proof: Delta,
    /// We can't support unbalanced transactions, so this is just a placeholder.
    pub expected_balance: Option<Vec<u8>>,
    /// The aggregation proof, if present, attesting to the validity of all individual proofs.
    pub aggregation_proof: Option<Vec<u8>>,
}

/// Represents either a delta witness for proving or a delta proof for verification.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Delta {
    /// The delta witness used for proving the delta proof.
    Witness(DeltaWitness),
    /// The delta proof used for verification.
    Proof(DeltaProof),
}

impl Transaction {
    /// Create a new transaction with the given actions and delta.
    /// Delta proof is a deterministic process, no proving key is needed.
    /// Delta instance can be constructed from the actions.
    pub fn create(actions: Vec<Action>, delta: Delta) -> Self {
        Transaction {
            actions,
            delta_proof: delta,
            expected_balance: None,
            aggregation_proof: None,
        }
    }

    /// Generates the delta proof for the transaction if it contains a delta witness.
    pub fn generate_delta_proof(self) -> Result<Transaction, ArmError> {
        match self.delta_proof {
            Delta::Witness(ref witness) => {
                let msg = self.get_delta_msg()?;
                let proof = DeltaProof::prove(&msg, witness)?;
                let delta_proof = Delta::Proof(proof);
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

    /// Verifies all the proofs and corresponding checks in the transaction.
    pub fn verify(self) -> Result<(), ArmError> {
        match &self.delta_proof {
            Delta::Proof(ref proof) => {
                let msg = self.get_delta_msg()?;
                let instance = self.delta()?;
                DeltaProof::verify(&msg, proof, instance)?;

                // Check for nullifier duplication across all compliance units
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
                    for action in self.actions {
                        action.verify()?;
                    }
                }
                Ok(())
            }
            Delta::Witness(_) => Err(ArmError::ExpectedDeltaProof),
        }
    }

    /// Inner check for nullifier duplication across all compliance units
    pub fn nf_duplication_check(&self) -> Result<(), ArmError> {
        let mut seen_nullifiers = std::collections::HashSet::new();
        for action in &self.actions {
            for cu in action.get_compliance_units() {
                let instance = cu.get_instance()?;
                if !seen_nullifiers.insert(instance.consumed_nullifier) {
                    return Err(ArmError::NullifierDuplication);
                }
            }
        }
        Ok(())
    }

    /// Returns the DeltaInstance constructed from the sum of all actions' deltas.
    pub fn delta(&self) -> Result<DeltaInstance, ArmError> {
        let mut points = Vec::with_capacity(self.actions.len());
        for action in &self.actions {
            points.push(action.delta()?);
        }
        DeltaInstance::from_deltas(&points)
    }

    /// Constructs the delta message by concatenating the delta messages
    /// of each action.
    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        let mut msg = Vec::new();
        for action in &self.actions {
            msg.extend(action.get_delta_msg()?);
        }
        Ok(msg)
    }

    /// Composes two transactions by concatenating their actions and combining their delta witnesses.
    pub fn compose(tx1: Transaction, tx2: Transaction) -> Transaction {
        let mut actions = tx1.actions;
        actions.extend(tx2.actions);
        let delta = match (&tx1.delta_proof, &tx2.delta_proof) {
            (Delta::Witness(witness1), Delta::Witness(witness2)) => {
                Delta::Witness(witness1.compose(witness2))
            }
            _ => panic!("Cannot compose transactions with different delta types"),
        };
        Transaction::create(actions, delta)
    }

    /// Returns `true` if any compliance or resource logic proof is `None`.
    pub fn base_proofs_are_empty(&self) -> bool {
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

    /// Returns all compliance units in the transaction.
    pub fn get_compliance_units(&self) -> Vec<&ComplianceUnit> {
        self.actions
            .iter()
            .flat_map(|a| a.get_compliance_units().iter())
            .collect()
    }

    /// Returns all compliance inner receipts in the transaction.
    pub fn get_compliance_inner_receipts(&self) -> Result<Vec<InnerReceipt>, ArmError> {
        let mut compliance_inner_receipts = Vec::new();
        for cu in self.get_compliance_units() {
            let inner_receipt = cu.get_inner_receipt()?;
            compliance_inner_receipts.push(inner_receipt);
        }
        Ok(compliance_inner_receipts)
    }

    /// Returns all logic inner receipts in the transaction.
    pub fn get_logic_inner_receipts(&self) -> Result<Vec<InnerReceipt>, ArmError> {
        let mut logic_inner_receipts = Vec::new();
        for action in self.actions.iter() {
            let logic_inputs = action.get_logic_verifier_inputs();
            for lp in logic_inputs.iter() {
                let inner_receipt = lp.get_inner_receipt()?;
                logic_inner_receipts.push(inner_receipt);
            }
        }
        Ok(logic_inner_receipts)
    }

    /// Returns all compliance instances in the transaction.
    pub fn get_compliance_instances(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        for cu in self.get_compliance_units() {
            result.push(cu.instance.clone());
        }
        result
    }

    /// Returns all logic verifiers in the transaction.
    pub fn get_logic_verifiers(&self) -> Result<Vec<LogicVerifier>, ArmError> {
        let mut result = Vec::new();
        for action in &self.actions {
            let logic_verifiers = action.get_logic_verifiers()?;
            result.extend(logic_verifiers);
        }
        Ok(result)
    }

    /// Returns all logic verifying keys and instances in the transaction.
    pub fn get_logic_vks_and_instances(&self) -> Result<(Vec<Digest>, Vec<Vec<u8>>), ArmError> {
        let mut vks = Vec::new();
        let mut instances = Vec::new();
        for lp in self.get_logic_verifiers()? {
            vks.push(lp.verifying_key);
            instances.push(lp.instance.clone());
        }
        Ok((vks, instances))
    }
}

#[cfg(feature = "aggregation")]
impl Transaction {
    /// Aggregates all the transaction proofs.
    /// If aggregation is successful, `self` contains an aggregation proof and its
    /// compliance and logic proofs are set to `None`. Else proofs are untouched.
    pub fn aggregate(&mut self, proof_type: ProofType) -> Result<(), ArmError> {
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
            .get_compliance_instances()
            .iter()
            .map(|instance_bytes| ComplianceInstanceWords::from_bytes(instance_bytes))
            .collect::<Result<Vec<ComplianceInstanceWords>, ArmError>>()?;

        let (lp_vks, lp_instances) = self.get_logic_vks_and_instances()?;
        let lp_instances_u32: Vec<Vec<u32>> = lp_instances
            .iter()
            .map(|instance_bytes| bytes_to_words(instance_bytes))
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

        self.erase_base_proofs();
        Ok(())
    }

    /// Verifies the aggregated proof of the transaction.
    pub fn verify_aggregation(&self) -> Result<(), ArmError> {
        if let Some(proof) = &self.aggregation_proof {
            let instance = self.construct_aggregation_instance()?;

            let inner_receipt: InnerReceipt = bincode::deserialize(proof)
                .map_err(|_| ArmError::InnerReceiptDeserializationError)?;

            // Verify proof on the batch instance.
            let receipt = Receipt::new(inner_receipt, instance);

            receipt.verify(*BATCH_AGGREGATION_VK).map_err(|err| {
                ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
            })
        } else {
            Err(ArmError::ProofVerificationFailed(
                "Missing aggregation proof".into(),
            ))
        }
    }

    /// Constructs the aggregation instance by serializing all compliance and logic instances.
    pub fn construct_aggregation_instance(&self) -> Result<Vec<u8>, ArmError> {
        let compliance_instances_u32: Vec<ComplianceInstanceWords> = self
            .get_compliance_instances()
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

    // Replaces all compliance and resource logic proofs with `None`.
    fn erase_base_proofs(&mut self) {
        for a in self.actions.iter_mut() {
            for cu in a.compliance_units.iter_mut() {
                cu.proof = None;
            }
            for lp in a.logic_verifier_inputs.iter_mut() {
                lp.proof = None;
            }
        }
    }
}

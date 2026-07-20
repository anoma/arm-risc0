//! Transaction structure and associated methods.

use crate::{aggregation_instance::AggregationInstance, constants::global_kind_table_hash};
#[cfg(all(feature = "aggregation", feature = "prove"))]
use crate::{
    aggregation_witness::{ActionWitness, AggregationWitness},
    constants::BATCH_AGGREGATION_PK,
    proving_system::ProofType,
};
#[cfg(feature = "aggregation")]
use crate::{
    constants::{BATCH_AGGREGATION_VK, COMPLIANCE_VK},
    utils::words_to_bytes,
};
#[cfg(feature = "aggregation")]
use risc0_zkvm::Receipt;
#[cfg(all(feature = "aggregation", feature = "prove"))]
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, VerifierContext};
use risc0_zkvm::{Digest, InnerReceipt};

use crate::{
    action::Action,
    compliance_unit::ComplianceUnit,
    delta_proof::{DeltaInstance, DeltaProof, DeltaWitness},
    error::ArmError,
    logic_proof::LogicVerifier,
};
use serde::{Deserialize, Serialize};

/// Aggregation proof and its decoded instance — always populated together.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Aggregation {
    /// Serialised `InnerReceipt` from the aggregation prover.
    pub proof: Vec<u8>,
    /// Typed journal decoded from the receipt — the canonical public output.
    pub instance: AggregationInstance,
}

/// Represents a transaction consisting of actions, delta proof, expected balance,
/// and optional aggregation proof.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Transaction {
    /// The actions included in the transaction.
    /// `Some` before aggregation; `None` once `aggregate()` succeeds.
    pub actions: Option<Vec<Action>>,
    /// The delta proof, which can be either a witness for proving or a proof for verification.
    pub delta_proof: Delta,
    /// We can't support unbalanced transactions, so this is just a placeholder.
    pub expected_balance: Option<Vec<u8>>,
    /// Present after `aggregate()` succeeds; `None` before aggregation.
    pub aggregation: Option<Aggregation>,
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
            actions: Some(actions),
            delta_proof: delta,
            expected_balance: None,
            aggregation: None,
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
                    aggregation: self.aggregation,
                })
            }
            Delta::Proof(_) => Ok(self),
        }
    }

    /// Verifies all the proofs and corresponding checks in the transaction.
    pub fn verify(&self) -> Result<(), ArmError> {
        // A transaction must carry exactly one representation. Rejecting the
        // "both present" case here prevents a crafted transaction from
        // pairing a genuine (but unrelated) aggregation proof with
        // unverified, attacker-controlled `actions` and having the delta /
        // nullifier checks silently run against the unverified `actions`
        // instead of the proof-backed `aggregation.instance`.
        self.check_representation()?;

        match &self.delta_proof {
            Delta::Proof(ref proof) => {
                let msg = self.get_delta_msg()?;
                let instance = self.delta()?;
                DeltaProof::verify(&msg, proof, instance)?;

                // Check for nullifier duplication across all compliance units
                self.nf_duplication_check()?;
                self.kind_table_commitment_check()?;

                if self.aggregation.is_some() {
                    #[cfg(not(feature = "aggregation"))]
                    return Err(ArmError::ProofVerificationFailed(
                        "feature `aggregation` is not enabled".into(),
                    ));

                    #[cfg(feature = "aggregation")]
                    self.verify_aggregation()?;
                } else {
                    let actions = self.actions.as_ref().ok_or(ArmError::MissingActions)?;
                    for action in actions {
                        action.verify()?;
                    }
                }
                Ok(())
            }
            Delta::Witness(_) => Err(ArmError::ExpectedDeltaProof),
        }
    }

    /// Ensures exactly one of `actions` / `aggregation` is populated.
    ///
    /// A `Transaction` is a plain deserializable struct, so nothing besides
    /// this check stops a crafted instance from carrying both fields at
    /// once. Callers must not derive authenticated data (delta, nullifiers)
    /// from `actions` unless this check has passed.
    pub fn check_representation(&self) -> Result<(), ArmError> {
        match (&self.actions, &self.aggregation) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (Some(_), Some(_)) => Err(ArmError::AmbiguousTransactionRepresentation),
            (None, None) => Err(ArmError::MissingActions),
        }
    }

    /// Checks that all compliance units in the transaction commit to the same kind table,
    /// and that the commitment matches the loaded global kind table.
    ///
    /// When `aggregation` is present it is authoritative: the commitment is
    /// read from the proof-backed `aggregation.instance` (cross-action
    /// consistency was already enforced in-circuit by the aggregation
    /// guest), never from `actions`, even if both happen to be populated.
    pub fn kind_table_commitment_check(&self) -> Result<(), ArmError> {
        let commitment = if let Some(agg) = &self.aggregation {
            agg.instance.kind_table_commitment
        } else if let Some(actions) = &self.actions {
            let mut iter = actions.iter();
            let Some(first) = iter.next() else {
                return Ok(());
            };
            let expected = first.compliance_unit.get_instance()?.kind_table_commitment;
            for action in iter {
                let commitment = action.compliance_unit.get_instance()?.kind_table_commitment;
                if commitment != expected {
                    return Err(ArmError::KindTableCommitmentMismatch);
                }
            }
            expected
        } else {
            return Err(ArmError::MissingActions);
        };

        let global_hash = global_kind_table_hash().ok_or(ArmError::KindTableNotLoaded)?;
        if commitment != *global_hash {
            return Err(ArmError::KindTableGlobalMismatch);
        }
        Ok(())
    }

    /// Inner check for nullifier duplication across all compliance units.
    ///
    /// When `aggregation` is present it is authoritative: nullifiers are
    /// read from the proof-backed `aggregation.instance`, never from
    /// `actions`, even if both happen to be populated on this value.
    pub fn nf_duplication_check(&self) -> Result<(), ArmError> {
        let mut seen_nullifiers = std::collections::HashSet::new();
        if let Some(agg) = &self.aggregation {
            for action in &agg.instance.actions {
                for consumed in &action.consumed_publics {
                    if !seen_nullifiers.insert(consumed.resource_nullifier) {
                        return Err(ArmError::NullifierDuplication);
                    }
                }
            }
        } else if let Some(actions) = &self.actions {
            for action in actions {
                let compliance_instance = action.compliance_unit.get_instance()?;
                for consumed_nullifier in compliance_instance
                    .consumed_publics
                    .iter()
                    .map(|r| r.resource_nullifier)
                {
                    if !seen_nullifiers.insert(consumed_nullifier) {
                        return Err(ArmError::NullifierDuplication);
                    }
                }
            }
        } else {
            return Err(ArmError::MissingActions);
        }
        Ok(())
    }

    /// Returns the DeltaInstance constructed from the sum of all actions' deltas.
    ///
    /// When `aggregation` is present it is authoritative; see
    /// [`Self::nf_duplication_check`].
    pub fn delta(&self) -> Result<DeltaInstance, ArmError> {
        if let Some(agg) = &self.aggregation {
            let mut points = Vec::with_capacity(agg.instance.actions.len());
            for action in &agg.instance.actions {
                points.push(action.delta_projective()?);
            }
            DeltaInstance::from_deltas(&points)
        } else if let Some(actions) = &self.actions {
            let mut points = Vec::with_capacity(actions.len());
            for action in actions {
                points.push(action.delta()?);
            }
            DeltaInstance::from_deltas(&points)
        } else {
            Err(ArmError::MissingActions)
        }
    }

    /// Constructs the delta message by concatenating the delta messages
    /// of each action.
    ///
    /// When `aggregation` is present it is authoritative; see
    /// [`Self::nf_duplication_check`].
    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        if let Some(agg) = &self.aggregation {
            let mut msg = Vec::new();
            for action in &agg.instance.actions {
                for consumed in &action.consumed_publics {
                    msg.extend_from_slice(consumed.resource_nullifier.as_bytes());
                }
                for created in &action.created_publics {
                    msg.extend_from_slice(created.resource_commitment.as_bytes());
                }
            }
            Ok(msg)
        } else if let Some(actions) = &self.actions {
            let mut msg = Vec::new();
            for action in actions {
                msg.extend(action.get_delta_msg()?);
            }
            Ok(msg)
        } else {
            Err(ArmError::MissingActions)
        }
    }

    /// Composes two transactions by concatenating their actions and combining their delta witnesses.
    /// Both transactions must carry a `Delta::Witness` and must not have been aggregated.
    pub fn compose(tx1: Transaction, tx2: Transaction) -> Result<Transaction, ArmError> {
        tx1.check_representation()
            .map_err(|_| ArmError::CannotComposeAggregated)?;
        tx2.check_representation()
            .map_err(|_| ArmError::CannotComposeAggregated)?;
        let actions1 = tx1.actions.ok_or(ArmError::CannotComposeAggregated)?;
        let actions2 = tx2.actions.ok_or(ArmError::CannotComposeAggregated)?;
        let mut actions = actions1;
        actions.extend(actions2);
        let delta = match (tx1.delta_proof, tx2.delta_proof) {
            (Delta::Witness(witness1), Delta::Witness(witness2)) => {
                Delta::Witness(witness1.compose(&witness2)?)
            }
            _ => return Err(ArmError::IncompatibleDeltaTypes),
        };
        Ok(Transaction::create(actions, delta))
    }

    /// Returns `true` if the transaction has no base proofs (i.e. it has already
    /// been aggregated and `actions` was cleared).
    pub fn base_proofs_are_empty(&self) -> bool {
        self.actions.is_none()
    }

    /// Returns all compliance units in the transaction.
    pub fn get_compliance_units(&self) -> Vec<&ComplianceUnit> {
        self.actions
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|a| &a.compliance_unit)
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
        for action in self.actions.as_deref().unwrap_or(&[]) {
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
        for action in self.actions.as_deref().unwrap_or(&[]) {
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

#[cfg(all(feature = "aggregation", feature = "prove"))]
impl Transaction {
    /// Aggregates all the transaction proofs.
    ///
    /// On success, `self.aggregation` is populated with the proof and decoded
    /// `AggregationInstance`, and `self.actions` is set to `None` (the
    /// individual proofs and witnesses are no longer needed).
    pub fn aggregate(&mut self, proof_type: ProofType) -> Result<(), ArmError> {
        if self.base_proofs_are_empty() {
            return Err(ArmError::ProveFailed(
                "Cannot aggregate: transaction has already been aggregated (actions is None)"
                    .into(),
            ));
        }

        let actions = self.actions.as_ref().ok_or(ArmError::MissingActions)?;

        if actions.is_empty() {
            return Err(ArmError::ProveFailed(
                "Cannot aggregate: transaction has no actions".into(),
            ));
        }
        let mut env_builder = ExecutorEnv::builder();
        let mut action_witnesses = Vec::with_capacity(actions.len());

        for action in actions {
            let compliance_instance = action.compliance_unit.get_instance()?;
            env_builder.add_assumption(action.compliance_unit.get_inner_receipt()?);

            // Positional matching: logic_verifier_inputs must be in canonical
            // tag order (consumed nullifiers then created commitments), which is
            // the same order ComplianceInstance::tags() produces. This mirrors
            // Action::get_logic_verifiers and avoids the silent overwrite that
            // a HashMap would cause when duplicate tags are present.
            let tags: Vec<Digest> = compliance_instance.tags().collect();
            if tags.len() != action.logic_verifier_inputs.len() {
                return Err(ArmError::TagNotFound);
            }
            let n_consumed = compliance_instance.consumed_publics.len();
            let (consumed_lvis, created_lvis) = action.logic_verifier_inputs.split_at(n_consumed);

            let mut consumed_app_data = Vec::with_capacity(n_consumed);
            for (lvi, tag) in consumed_lvis.iter().zip(&tags[..n_consumed]) {
                if lvi.tag != *tag {
                    return Err(ArmError::TagNotFound);
                }
                env_builder.add_assumption(lvi.get_inner_receipt()?);
                consumed_app_data.push(lvi.app_data.clone());
            }

            let mut created_app_data =
                Vec::with_capacity(compliance_instance.created_publics.len());
            for (lvi, tag) in created_lvis.iter().zip(&tags[n_consumed..]) {
                if lvi.tag != *tag {
                    return Err(ArmError::TagNotFound);
                }
                env_builder.add_assumption(lvi.get_inner_receipt()?);
                created_app_data.push(lvi.app_data.clone());
            }

            action_witnesses.push(ActionWitness {
                compliance_instance,
                consumed_app_data,
                created_app_data,
            });
        }

        let witnesses = AggregationWitness {
            compliance_key: *COMPLIANCE_VK,
            actions: action_witnesses,
        };

        let env = env_builder
            .write(&witnesses)
            .map_err(|_| ArmError::WriteWitnessFailed)?
            .build()
            .map_err(|_| ArmError::BuildProverEnvFailed)?;

        let prover_opts = match proof_type {
            ProofType::Succinct => ProverOpts::succinct(),
            ProofType::Groth16 => ProverOpts::groth16(),
        };

        let prover = default_prover();

        // Prove batch.
        let agg_receipt = prover
            .prove_with_ctx(
                env,
                &VerifierContext::default(),
                BATCH_AGGREGATION_PK,
                &prover_opts,
            )
            .map_err(|err| ArmError::ProveFailed(format!("Proof generation failed: {}", err)))?
            .receipt;

        // Decode the AggregationInstance from the journal.
        let instance: AggregationInstance = agg_receipt
            .journal
            .decode()
            .map_err(|_| ArmError::InstanceSerializationFailed)?;

        let proof =
            bincode::serialize(&agg_receipt.inner).map_err(|_| ArmError::SerializationError)?;

        self.aggregation = Some(Aggregation { proof, instance });
        self.actions = None;
        Ok(())
    }
}

#[cfg(feature = "aggregation")]
impl Transaction {
    /// Verifies the aggregated proof of the transaction.
    pub fn verify_aggregation(&self) -> Result<(), ArmError> {
        let agg = self
            .aggregation
            .as_ref()
            .ok_or_else(|| ArmError::ProofVerificationFailed("Missing aggregation".into()))?;

        let instance_bytes = risc0_zkvm::serde::to_vec(&agg.instance)
            .map_err(|_| ArmError::InstanceSerializationFailed)?;

        let inner_receipt: InnerReceipt = bincode::deserialize(&agg.proof)
            .map_err(|_| ArmError::InnerReceiptDeserializationError)?;

        let receipt = Receipt::new(inner_receipt, words_to_bytes(&instance_bytes).to_vec());

        receipt.verify(*BATCH_AGGREGATION_VK).map_err(|err| {
            ArmError::ProofVerificationFailed(format!("Proof verification failed: {}", err))
        })?;

        if agg.instance.compliance_key != *COMPLIANCE_VK {
            return Err(ArmError::ProofVerificationFailed(
                "aggregation compliance_key does not match expected COMPLIANCE_VK".into(),
            ));
        }

        Ok(())
    }
}

use crate::{
    action::Action,
    delta_proof::{DeltaInstance, DeltaProof, DeltaWitness},
    error::ArmError,
};
#[cfg(feature = "aggregation")]
use crate::{
    aggregation::{
        batch::BatchAggregation, sequential::SequentialAggregation, AggregationProof,
        AggregationStrategy,
    },
    proving_system::ProofType,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction {
    pub actions: Vec<Action>,
    // delta verification is a deterministic process, so we don't need a
    // separate delta_vk here.
    pub delta_proof: Delta,
    // We can't support unbalanced transactions, so this is just a placeholder.
    pub expected_balance: Option<Vec<u8>>,
    // If present, attests to the validity of all individual proofs.
    pub aggregation_proof: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Delta {
    Witness(DeltaWitness),
    Proof(DeltaProof),
}

impl Transaction {
    // Create a new transaction with the given actions and delta.
    // Delta proof is a deterministic process, no proving key is needed.
    // Delta instance can be constructed from the actions.
    pub fn create(actions: Vec<Action>, delta: Delta) -> Self {
        Transaction {
            actions,
            delta_proof: delta,
            expected_balance: None,
            aggregation_proof: None,
        }
    }

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

    // Returns the DeltaInstance constructed from the sum of all actions'
    // deltas.
    pub fn delta(&self) -> Result<DeltaInstance, ArmError> {
        let mut points = Vec::with_capacity(self.actions.len());
        for action in &self.actions {
            points.push(action.delta()?);
        }
        DeltaInstance::from_deltas(&points)
    }

    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        let mut msg = Vec::new();
        for action in &self.actions {
            msg.extend(action.get_delta_msg()?);
        }
        Ok(msg)
    }

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
}

#[cfg(feature = "aggregation")]
impl Transaction {
    /// Aggregates all the transaction proofs with the default strategy.
    pub fn aggregate(&mut self, proof_type: ProofType) -> Result<(), ArmError> {
        self.aggregate_with_strategy(AggregationStrategy::Batch, proof_type)
    }

    /// Aggregates all the transaction proofs using the passed aggregation strategy.
    /// If aggregation is successful, `self` contains an aggregation proof and its
    /// compliance and logic proofs are set to `None`. Else proofs are untouched.
    pub fn aggregate_with_strategy(
        &mut self,
        strategy: AggregationStrategy,
        proof_type: ProofType,
    ) -> Result<(), ArmError> {
        let agg_proof = match strategy {
            AggregationStrategy::Sequential => {
                SequentialAggregation::prove_transaction_aggregation(self, proof_type)
                    .map(AggregationProof::Sequential)?
            }
            AggregationStrategy::Batch => {
                BatchAggregation::prove_transaction_aggregation(self, proof_type)
                    .map(AggregationProof::Batch)?
            }
        };

        self.aggregation_proof =
            Some(bincode::serialize(&agg_proof).map_err(|_| ArmError::SerializationError)?);

        self.erase_base_proofs();
        Ok(())
    }

    /// Verifies the aggregated proof of the transaction.
    pub fn verify_aggregation(&self) -> Result<(), ArmError> {
        if let Some(agg_proof) = &self.aggregation_proof {
            match bincode::deserialize(agg_proof)
                .map_err(|_| ArmError::InnerReceiptDeserializationError)?
            {
                AggregationProof::Sequential(proof) => {
                    SequentialAggregation::verify_transaction_aggregation(self, &proof)
                }
                AggregationProof::Batch(proof) => {
                    BatchAggregation::verify_transaction_aggregation(self, &proof)
                }
            }
        } else {
            Err(ArmError::ProofVerificationFailed(
                "Missing aggregation proof".into(),
            ))
        }
    }

    pub fn get_raw_aggregation_proof(&self) -> Option<Vec<u8>> {
        if let Some(agg_proof) = &self.aggregation_proof {
            match bincode::deserialize(agg_proof).unwrap() {
                AggregationProof::Sequential(proof) => Some(bincode::serialize(&proof.0).unwrap()),
                AggregationProof::Batch(proof) => Some(bincode::serialize(&proof.0).unwrap()),
            }
        } else {
            None
        }
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

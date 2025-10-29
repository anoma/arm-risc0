#[cfg(feature = "aggregation")]
use crate::aggregation::{
    batch::BatchAggregation, sequential::SequentialAggregation, AggregationProof,
    AggregationStrategy,
};
use crate::{
    action::Action,
    compliance::TX_MAX_RESOURCES,
    compliance_unit::{CUInner, CUI},
    constants::COMPLIANCE_SIGMABUS_VK,
    delta_proof::{DeltaInstance, DeltaProof, DeltaWitness},
    error::ArmError,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction<ComplianceUnit: CUI> {
    pub actions: Vec<Action<ComplianceUnit>>,
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

impl<ComplianceUnit: CUInner> Transaction<ComplianceUnit> {
    // Create a new transaction with the given actions and delta.
    // Delta proof is a deterministic process, no proving key is needed.
    // Delta instance can be constructed from the actions.
    pub fn create(actions: Vec<Action<ComplianceUnit>>, delta: Delta) -> Self {
        Transaction {
            actions,
            delta_proof: delta,
            expected_balance: None,
            aggregation_proof: None,
        }
    }

    pub fn generate_delta_proof(self) -> Result<Transaction<ComplianceUnit>, ArmError> {
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
                for action in self.actions {
                    action.verify()?;
                }
                Ok(())
            }
            Delta::Witness(_) => Err(ArmError::ExpectedDeltaProof),
        }
    }

    /// Returns the [DeltaInstance] constructed from the sum of all actions'
    /// deltas.
    fn delta(&self) -> Result<DeltaInstance, ArmError> {
        if ComplianceUnit::verifying_key() == *COMPLIANCE_SIGMABUS_VK
            && TX_MAX_RESOURCES < self.number_resources()?
        {
            // Reached maximum number of resources.
            return Err(ArmError::DeltaProofVerificationFailed);
        }

        let mut points = Vec::with_capacity(self.actions.len());
        for action in &self.actions {
            points.push(action.delta()?);
        }
        DeltaInstance::from_deltas(&points)
    }

    /// Returns the number of resources in this [Transaction].
    fn number_resources(&self) -> Result<usize, ArmError> {
        let mut n = 1;
        for a in self.actions.iter() {
            for cu in a.compliance_units.iter() {
                n += cu.created()?.len() + cu.consumed()?.len()
            }
        }
        Ok(n)
    }

    pub fn get_delta_msg(&self) -> Result<Vec<u8>, ArmError> {
        let mut msg = Vec::new();
        for action in &self.actions {
            msg.extend(action.get_delta_msg()?);
        }
        Ok(msg)
    }

    pub fn compose(
        tx1: Transaction<ComplianceUnit>,
        tx2: Transaction<ComplianceUnit>,
    ) -> Transaction<ComplianceUnit> {
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
impl<ComplianceUnit: CUInner> Transaction<ComplianceUnit> {
    /// Aggregates all the transaction proofs with the default strategy.
    pub fn aggregate(&mut self) -> Result<(), ArmError> {
        self.aggregate_with_strategy(AggregationStrategy::Batch)
    }

    /// Aggregates all the transaction proofs using the passed aggregation strategy.
    /// If aggregation is successful, `self` contains an aggregation proof and its
    /// compliance and logic proofs are set to `None`. Else proofs are untouched.
    pub fn aggregate_with_strategy(
        &mut self,
        strategy: AggregationStrategy,
    ) -> Result<(), ArmError> {
        let agg_proof = match strategy {
            AggregationStrategy::Sequential => {
                SequentialAggregation::prove_transaction_aggregation(self)
                    .map(AggregationProof::Sequential)?
            }
            AggregationStrategy::Batch => BatchAggregation::prove_transaction_aggregation(self)
                .map(AggregationProof::Batch)?,
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
                cu.unset_circuit_proof();
            }
            for lp in a.logic_verifier_inputs.iter_mut() {
                lp.proof = None;
            }
        }
    }
}

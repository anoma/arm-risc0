#[cfg(feature = "aggregation")]
use crate::aggregation::{
    batch::BatchAggregation, sequential::SequentialAggregation, AggregationProof,
    AggregationStrategy,
};
use crate::{
    action::Action,
    delta_proof::{DeltaInstance, DeltaProof, DeltaWitness},
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "nif")]
use {rustler::NifStruct, rustler::NifTaggedEnum};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.Transaction")]
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
#[cfg_attr(feature = "nif", derive(NifTaggedEnum))]
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

    pub fn generate_delta_proof(&mut self) {
        match self.delta_proof {
            Delta::Witness(ref witness) => {
                let msg = self.get_delta_msg();
                let proof = DeltaProof::prove(&msg, witness);
                self.delta_proof = Delta::Proof(proof);
            }
            Delta::Proof(_) => {}
        }
    }

    pub fn verify(self) -> bool {
        match &self.delta_proof {
            Delta::Proof(ref proof) => {
                let msg = self.get_delta_msg();
                let instance = self.delta();
                if DeltaProof::verify(&msg, proof, instance).is_err() {
                    return false;
                }
                for action in self.actions {
                    if !action.verify() {
                        return false;
                    }
                }
                true
            }
            Delta::Witness(_) => false,
        }
    }

    // Returns the DeltaInstance constructed from the sum of all actions'
    // deltas.
    pub fn delta(&self) -> DeltaInstance {
        let deltas = self
            .actions
            .iter()
            .map(|action| action.delta())
            .collect::<Vec<_>>();
        DeltaInstance::from_deltas(&deltas).unwrap()
    }

    pub fn get_delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for action in &self.actions {
            msg.extend(action.get_delta_msg());
        }
        msg
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
    pub fn aggregate(&mut self) -> Option<()> {
        self.aggregate_with_strategy(AggregationStrategy::Batch)
    }

    /// Aggregates all the transaction proofs using the passed aggregation strategy.
    /// If aggregation is successful, `self` contains an aggregation proof and its
    /// compliance and logic proofs are set to `None`. Else proofs are untouched.
    pub fn aggregate_with_strategy(&mut self, strategy: AggregationStrategy) -> Option<()> {
        let agg_proof = match strategy {
            AggregationStrategy::Sequential => {
                SequentialAggregation::prove_transaction_aggregation(self)
                    .map(AggregationProof::Sequential)
            }
            AggregationStrategy::Batch => {
                BatchAggregation::prove_transaction_aggregation(self).map(AggregationProof::Batch)
            }
        };

        if agg_proof.is_some() {
            self.aggregation_proof = bincode::serialize(&agg_proof.unwrap()).ok();
        }

        if self.aggregation_proof.is_some() {
            self.erase_base_proofs();
            Some(())
        } else {
            // Do nothing.
            None
        }
    }

    /// Verifies the aggregated proof of the transaction.
    pub fn verify_aggregation(&self) -> Option<()> {
        let agg_proof = bincode::deserialize(&self.aggregation_proof.clone().unwrap()).ok();

        match agg_proof? {
            AggregationProof::Sequential(proof) => {
                SequentialAggregation::verify_transaction_aggregation(self, &proof)
            }
            AggregationProof::Batch(proof) => {
                BatchAggregation::verify_transaction_aggregation(self, &proof)
            }
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

pub fn generate_test_transaction(n_actions: usize) -> Transaction {
    use crate::action::create_multiple_actions;
    let (actions, delta_witness) = create_multiple_actions(n_actions);
    let mut tx = Transaction::create(actions, Delta::Witness(delta_witness));
    tx.generate_delta_proof();
    assert!(tx.clone().verify());
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction() {
        let _ = generate_test_transaction(1);
    }

    #[test]
    #[cfg(feature = "aggregation")]
    fn test_aggregation_works() {
        let tx = generate_test_transaction(1);

        for strategy in vec![AggregationStrategy::Sequential, AggregationStrategy::Batch] {
            let mut tx_str = tx.clone();
            tx_str.aggregate_with_strategy(strategy.clone());
            assert_eq!(true, tx_str.aggregation_proof.is_some());
            assert_eq!(true, tx_str.verify_aggregation().is_some());
        }
    }

    #[test]
    #[cfg(feature = "aggregation")]
    fn test_verify_aggregation_fails_for_incorrect_instances() {
        let tx = generate_test_transaction(2);

        for strategy in vec![AggregationStrategy::Sequential, AggregationStrategy::Batch] {
            let mut tx_str = tx.clone();
            tx_str.aggregate_with_strategy(strategy);

            tx_str.actions[0].logic_verifier_inputs.pop();

            assert_eq!(false, tx_str.verify_aggregation().is_some());
        }
    }

    #[test]
    #[cfg(feature = "aggregation")]
    fn test_cannot_aggregate_invalid_proofs() {
        use crate::logic_proof::LogicVerifierInputs;

        let tx = generate_test_transaction(2);

        // Create a transaction with one invalid proof.
        let bad_lproof = LogicVerifierInputs {
            proof: tx.actions[0].logic_verifier_inputs[0].clone().proof,
            verifying_key: vec![666u32; 8], // Bad key.
            tag: tx.actions[0].logic_verifier_inputs[0].tag.clone(),
            app_data: tx.actions[0].logic_verifier_inputs[0].app_data.clone(),
        };

        let bad_action = Action {
            compliance_units: tx.actions[0].clone().compliance_units,
            logic_verifier_inputs: vec![bad_lproof],
        };
        let bad_tx = Transaction::create(vec![bad_action, tx.actions[1].clone()], tx.delta_proof);

        for strategy in vec![AggregationStrategy::Sequential, AggregationStrategy::Batch] {
            let mut bad_tx_str = bad_tx.clone();
            bad_tx_str.aggregate_with_strategy(strategy);
            assert_eq!(true, bad_tx_str.aggregation_proof.is_none());
        }
    }
}

use super::pcd::PcdProof;
use crate::{aggregation::sequential::SequentialAggregation, transaction::Transaction};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum AggregationProof {
    /// A PCD-base aggregation proof generated with a sequential transcript.
    Sequential(PcdProof),
}

impl AggregationProof {
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        match self {
            AggregationProof::Sequential(proof) => {
                // TODO: Serialize only the inner receipt.(To do so, need ability to go from `PcdMessage` to `Journal` when verifying.)
                bincode::serialize(&(AggregationStrategy::Sequential, proof.clone().0)).ok()
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<AggregationProof> {
        let de: Result<(AggregationStrategy, Receipt), _> = bincode::deserialize(bytes);
        match de {
            Ok((AggregationStrategy::Sequential, proof)) => {
                Some(AggregationProof::Sequential(PcdProof(proof)))
            }
            _ => None,
        }
    }
}

/// Supported strategies to aggregate.
#[derive(Debug, Serialize, Deserialize)]
pub enum AggregationStrategy {
    Sequential,
}

impl Transaction {
    pub fn default_aggregation(&mut self) {
        self.aggregate(AggregationStrategy::Sequential)
    }

    // TODO: Erase compliance and logic proofs.
    pub fn aggregate(&mut self, strategy: AggregationStrategy) {
        match strategy {
            AggregationStrategy::Sequential => {
                if let Some(proof) = SequentialAggregation::prove_transaction_aggregation(self) {
                    self.aggregation_proof = AggregationProof::Sequential(proof).to_bytes();
                }
            }
        }
    }

    pub fn verify_aggregation(&self) -> bool {
        if self.aggregation_proof.is_none() {
            return false;
        }
        let agg_proof = AggregationProof::from_bytes(&self.aggregation_proof.clone().unwrap());

        match agg_proof {
            Some(AggregationProof::Sequential(proof)) => {
                SequentialAggregation::verify_transaction_aggregation(self, &proof)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    // Run them with RISC0_DEV_MODE=1
    use super::AggregationStrategy;
    use crate::{
        action::Action,
        logic_proof::LogicProof,
        transaction::{generate_test_transaction, Transaction},
    };

    #[test]
    fn test_aggregation_works() {
        let mut tx = generate_test_transaction(1);

        // Sequential aggregation.
        tx.aggregate(AggregationStrategy::Sequential);
        assert_eq!(true, tx.aggregation_proof.is_some());
        assert_eq!(true, tx.verify_aggregation());
    }

    #[test]
    fn test_verify_fails_for_incorrect_instances() {
        let mut tx = generate_test_transaction(2);

        // Sequential aggregation.
        tx.aggregate(AggregationStrategy::Sequential);

        tx.actions[0].logic_verifier_inputs.pop();

        assert_eq!(false, tx.verify_aggregation());
    }

    #[test]
    fn test_cannot_aggregate_invalid_proofs() {
        let tx = generate_test_transaction(2);

        // Create a transaction with one invalid proof.
        let bad_lproof = LogicProof {
            proof: tx.actions[0].logic_verifier_inputs[0].clone().proof,
            instance: tx.actions[0].logic_verifier_inputs[0].clone().instance,
            //receipt: tx.actions[0].logic_proofs[0].receipt.clone(),
            verifying_key: vec![66u8; 32], // Bad key.
        };

        let bad_action = Action::new(
            tx.actions[0].clone().compliance_units,
            vec![bad_lproof],
            tx.actions[0].clone().resource_forwarder_calldata_pairs,
        );
        let mut bad_tx =
            Transaction::create(vec![bad_action, tx.actions[1].clone()], tx.delta_proof);

        // Sequential aggregation
        bad_tx.aggregate(AggregationStrategy::Sequential);
        assert_eq!(true, bad_tx.aggregation_proof.is_none());
    }
}

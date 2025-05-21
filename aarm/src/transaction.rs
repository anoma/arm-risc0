use crate::action::{create_an_action, create_multiple_actions};
use crate::{action::Action, evm_adapter::AdapterTransaction};
use aarm_core::delta_proof::{DeltaInstance, DeltaProof, DeltaWitness};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction {
    pub action: Vec<Action>,
    pub delta_proof: Delta,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Delta {
    Witness(DeltaWitness),
    Proof(DeltaProof),
}

impl Transaction {
    pub fn new(action: Vec<Action>, delta: Delta) -> Self {
        Transaction {
            action,
            delta_proof: delta,
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

    pub fn verify(&self) -> bool {
        match &self.delta_proof {
            Delta::Proof(ref proof) => {
                let msg = self.get_delta_msg();
                let instance = self.get_delta_instance();
                if DeltaProof::verify(&msg, proof, instance).is_err() {
                    return false;
                }
                for action in &self.action {
                    if !action.verify() {
                        return false;
                    }
                }
                true
            }
            Delta::Witness(_) => false,
        }
    }

    pub fn get_delta_instance(&self) -> DeltaInstance {
        let deltas = self
            .action
            .iter()
            .flat_map(|action| action.get_delta())
            .collect::<Vec<_>>();
        DeltaInstance::from_deltas(&deltas).unwrap()
    }

    pub fn get_delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for action in &self.action {
            msg.extend(action.get_delta_msg());
        }
        msg
    }

    pub fn compose(tx1: Transaction, tx2: Transaction) -> Transaction {
        let mut action = tx1.action;
        action.extend(tx2.action);
        let delta = match (&tx1.delta_proof, &tx2.delta_proof) {
            (Delta::Witness(witness1), Delta::Witness(witness2)) => {
                Delta::Witness(witness1.compose(witness2))
            }
            _ => panic!("Cannot compose transactions with different delta types"),
        };
        Transaction::new(action, delta)
    }

    pub fn convert(&self) -> AdapterTransaction {
        let actions = self.action.iter().map(|action| action.convert()).collect();
        let delta_proof = match &self.delta_proof {
            Delta::Witness(_) => panic!("Unbalanced Transactions cannot be converted"),
            Delta::Proof(proof) => proof.to_bytes().to_vec(),
        };
        AdapterTransaction {
            actions,
            delta_proof,
        }
    }
}

pub fn generate_test_transaction() -> Transaction {
    let (action, delta_witness) = create_an_action(1);
    let mut tx = Transaction::new(vec![action], Delta::Witness(delta_witness));
    tx.generate_delta_proof();
    assert!(tx.verify()); // TODO move into separate test
    let _adapter_tx = tx.convert();
    tx
}

pub fn generate_test_transaction_with_multiple_actions(n: usize) -> Transaction {
    let (actions, delta_witness) = create_multiple_actions(n);
    let mut tx = Transaction::new(actions, Delta::Witness(delta_witness));
    tx.generate_delta_proof();
    assert!(tx.verify()); // TODO move into separate test
    let _adapter_tx = tx.convert();
    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction() {
        let _ = generate_test_transaction();
    }

    #[test]
    fn test_transaction_with_multiple_actions() {
        let _ = generate_test_transaction_with_multiple_actions(2);
    }
}

use crate::{
    action::Action,
    delta_proof::{DeltaInstance, DeltaProof, DeltaWitness},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", serde(rename = "Elixir.Anoma.Arm.Transaction"))]
pub struct Transaction {
    pub actions: Vec<Action>,
    // delta verification is a deterministic process, so we don't need a
    // separate delta_vk here.
    pub delta_proof: Delta,
    // We can't support unbalanced transactions, so this is just a placeholder.
    pub expected_balance: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", serde(rename = "Elixir.Anoma.Arm.Delta"))]
pub enum Delta {
    #[cfg_attr(feature = "nif", serde(rename = "Elixir.Anoma.Arm.DeltaWitness"))]
    Witness(DeltaWitness),
    #[cfg_attr(feature = "nif", serde(rename = "Elixir.Anoma.Arm.DeltaProof"))]
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

#[cfg(feature = "prove")]
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
}

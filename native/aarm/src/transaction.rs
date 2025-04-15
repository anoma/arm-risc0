use crate::action::Action;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::tests::create_an_action;

    pub fn generate_test_transaction() -> Transaction {
        let (action, delta_witness) = create_an_action();
        let mut tx = Transaction::new(vec![action], Delta::Witness(delta_witness));
        tx.generate_delta_proof();
        assert!(tx.verify());

        tx
    }

    #[test]
    fn test_transaction() {
        let _ = generate_test_transaction();
    }
}

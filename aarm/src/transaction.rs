use crate::action::create_multiple_actions;
use crate::action::Action;
use aarm_core::delta_proof::{DeltaInstance, DeltaProof, DeltaWitness};
use serde::{Deserialize, Serialize};

#[cfg(feature = "nif")]
use {
     rustler::NifStruct,
     rustler::NifTaggedEnum,
};


#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.Transacttion")]
pub struct Transaction {
    pub actions: Vec<Action>,
    pub delta_proof: Delta,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[cfg_attr(feature = "nif", derive(NifTaggedEnum))]
pub enum Delta {
    Witness(DeltaWitness),
    Proof(DeltaProof),
}

impl Transaction {
    pub fn new(actions: Vec<Action>, delta: Delta) -> Self {
        Transaction {
            actions,
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
                for action in &self.actions {
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
            .actions
            .iter()
            .flat_map(|action| action.get_delta())
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
        Transaction::new(actions, delta)
    }
}

pub fn generate_test_transaction(n_actions: usize) -> Transaction {
    let (actions, delta_witness) = create_multiple_actions(n_actions);
    let mut tx = Transaction::new(actions, Delta::Witness(delta_witness));
    tx.generate_delta_proof();
    assert!(tx.verify());
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

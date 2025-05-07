use crate::types as EVMTypes;
use aarm_core::compliance::ComplianceInstance;
use aarm_core::constants::DEFAULT_BYTES;
use aarm_core::resource::Resource;
use aarm::transaction::Transaction;
use aarm::action::Action;
use alloy::primitives::{B256, U256};



impl From<Resource> for EVMTypes::Resource {
    fn from(r: Resource) -> Self {
        Self {
            logicRef: B256::from_slice(r.logic_ref.as_bytes()),
            labelRef: B256::from_slice(r.label_ref.as_bytes()),
            quantity: U256::from(r.quantity),
            valueRef: B256::from_slice(r.value_ref.as_bytes()),
            ephemeral: r.is_ephemeral,
            nonce: U256::from_le_slice(r.nonce.as_slice()),
            nullifierKeyCommitment: B256::from_slice(r.nk_commitment.inner().as_bytes()),
            randSeed: U256::from_le_slice(r.rand_seed.as_slice()),
        }
    }
}

impl From<ComplianceInstance> for EVMTypes::ComplianceInstance {
    fn from(c: ComplianceInstance) -> Self {
        Self {
            consumed: EVMTypes::ConsumedRefs {
                nullifier: B256::from_slice(c.nullifier.as_bytes()),
                root: B256::from_slice(c.merkle_root.as_bytes()),
                logicRef: B256::from_slice(c.consumed_logic_ref.as_bytes()),
            },
            created: EVMTypes::CreatedRefs {
                commitment: B256::from_slice(c.commitment.as_bytes()),
                logicRef: B256::from_slice(c.created_logic_ref.as_bytes()),
            },
            unitDelta: {
                let (left, right) = c.delta.as_bytes().split_at(DEFAULT_BYTES / 2);
                let left_bytes: [u8; 16] = left.try_into().unwrap();
                let right_bytes: [u8; 16] = right.try_into().unwrap();
                [
                    U256::from_le_bytes(left_bytes),
                    U256::from_le_bytes(right_bytes),
                ]
            },
        }
    }
}

/* // TODO: Implement
impl From<ComplianceUnit> for EVMTypes::ComplianceUnit {
    fn from(tx: ComplianceUnit) -> Self {}
}
impl From<TagLogicProofPair> for EVMTypes::TagLogicProofPair {
    fn from(tx: TagLogicProofPair) -> Self {}
}
impl From<Action> for EVMTypes::Action {
    fn from(tx: Action) -> Self {}
}
impl From<Transaction> for EVMTypes::Transaction {
    fn from(tx: Transaction) -> Self {}
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use aarm_core::nullifier_key::NullifierKeyCommitment;
    use aarm_core::resource::Resource;

    #[test]
    fn convert_resource() {
        let logic_ref = &[0x11; 32];
        let label_ref = &[0x22; 32];
        let value_ref = &[0x33; 32];
        let nkc = &[0x44; 32];
        let quantity = 55;
        let nonce = U256::from(66);
        let rand_seed = U256::from(77);
        let ephemeral = true;

        let expected = EVMTypes::Resource {
            logicRef: B256::from_slice(logic_ref),
            labelRef: B256::from_slice(label_ref),
            valueRef: B256::from_slice(value_ref),
            nullifierKeyCommitment: B256::from_slice(nkc),
            quantity: U256::from(quantity),
            nonce,
            randSeed: rand_seed,
            ephemeral,
        };

        let aarm = Resource {
            logic_ref: (*logic_ref).into(),
            label_ref: (*label_ref).into(),
            value_ref: (*value_ref).into(),
            nk_commitment: NullifierKeyCommitment::from_bytes((*nkc).into()),
            quantity,
            nonce: nonce.to_le_bytes(),
            rand_seed: rand_seed.to_le_bytes(),
            is_ephemeral: ephemeral,
        };

        let converted: EVMTypes::Resource = aarm.into();

        assert_eq!(converted.logicRef, expected.logicRef);
        assert_eq!(converted.labelRef, expected.labelRef);
        assert_eq!(converted.valueRef, expected.valueRef);
        assert_eq!(
            converted.nullifierKeyCommitment,
            expected.nullifierKeyCommitment
        );
        assert_eq!(converted.quantity, expected.quantity);
        assert_eq!(converted.nonce, expected.nonce);
        assert_eq!(converted.randSeed, expected.randSeed);
        assert_eq!(converted.ephemeral, expected.ephemeral);
    }
}

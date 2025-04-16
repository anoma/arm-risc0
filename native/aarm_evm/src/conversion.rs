use crate::types as EVMTypes;
use aarm_core::compliance::ComplianceInstance;
use aarm_core::constants::DEFAULT_BYTES;
use aarm_core::resource::Resource;
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
                nullifierRef: B256::from_slice(c.nullifier.as_bytes()),
                rootRef: B256::from_slice(c.merkle_root.as_bytes()),
                logicRef: B256::from_slice(c.consumed_logic_ref.as_bytes()),
            },
            created: EVMTypes::CreatedRefs {
                commitmentRef: B256::from_slice(c.commitment.as_bytes()),
                logicRef: B256::from_slice(c.created_logic_ref.as_bytes()),
            },
            unitDelta: {
                let (left, right) = c.delta.split_at(DEFAULT_BYTES / 2);
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

// fn evm_delta_proof(deltaProof: DeltaProof) -> Bytes {}

/* TODO
- [ ] Write method to fetch merkle path for the compliance proof
- [ ] Write conversion methods for
    - [x] resource
    - [ ] action
    - [ ] transaction
    - [ ] proof instances and proofs

- [ ] Method to call verify & execute on the PA
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

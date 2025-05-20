use alloy::sol;

use aarm::evm_adapter::{
    AdapterAction, AdapterComplianceUnit, AdapterLogicProof, AdapterTransaction,
};
use aarm_core::compliance::ComplianceInstance;
use aarm_core::constants::DEFAULT_BYTES;
use aarm_core::logic_instance::{ExpirableBlob, LogicInstance};
use aarm_core::resource::Resource;
use alloy::primitives::{B256, U256};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ProtocolAdapter,
    "src/ProtocolAdapter.json"
);

impl From<Resource> for ProtocolAdapter::Resource {
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

impl From<ComplianceInstance> for ProtocolAdapter::ComplianceInstance {
    fn from(c: ComplianceInstance) -> Self {
        Self {
            consumed: ProtocolAdapter::ConsumedRefs {
                nullifier: B256::from_slice(c.nullifier.as_bytes()),
                root: B256::from_slice(c.merkle_root.as_bytes()),
                logicRef: B256::from_slice(c.consumed_logic_ref.as_bytes()),
            },
            created: ProtocolAdapter::CreatedRefs {
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

impl From<ExpirableBlob> for ProtocolAdapter::ExpirableBlob {
    fn from(expirable_blob: ExpirableBlob) -> Self {
        Self {
            blob: expirable_blob.blob.into(),
            deletionCriterion: expirable_blob.deletion_criterion,
        }
    }
}

/* TODO figure this one out
impl From<Vec<ExpirableBlob>> for Vec<EVMTypes::ExpirableBlob> {
    fn from(blobs: Vec<ExpirableBlob>) -> Self {}
}*/

impl From<LogicInstance> for ProtocolAdapter::LogicInstance {
    fn from(instance: LogicInstance) -> Self {
        Self {
            tag: B256::from_slice(instance.tag.as_bytes()),
            isConsumed: instance.is_consumed,
            root: B256::from_slice(instance.root.as_bytes()),
            ciphertext: instance.cipher.into(),
            appData: instance.app_data.into_iter().map(|b| b.into()).collect(), // TODO Refactor (see above).
        }
    }
}

impl From<AdapterLogicProof> for ProtocolAdapter::LogicProof {
    fn from(logic_proof: AdapterLogicProof) -> Self {
        Self {
            proof: logic_proof.proof.into(),
            instance: logic_proof.instance.into(),
            logicRef: B256::from_slice(logic_proof.verifying_key.as_bytes()),
        }
    }
}

impl From<AdapterComplianceUnit> for ProtocolAdapter::ComplianceUnit {
    fn from(compliance_unit: AdapterComplianceUnit) -> Self {
        Self {
            proof: compliance_unit.proof.into(),
            instance: compliance_unit.instance.into(),
        }
    }
}

impl From<AdapterAction> for ProtocolAdapter::Action {
    fn from(action: AdapterAction) -> Self {
        Self {
            logicProofs: action
                .logic_proofs
                .into_iter()
                .map(|lp| lp.into())
                .collect(),
            complianceUnits: action
                .compliance_units
                .into_iter()
                .map(|cu| cu.into())
                .collect(),
            resourceCalldataPairs: vec![],
        }
    }
}

impl From<AdapterTransaction> for ProtocolAdapter::Transaction {
    fn from(tx: AdapterTransaction) -> Self {
        Self {
            actions: tx.actions.into_iter().map(|a| a.into()).collect(),
            deltaProof: tx.delta_proof.into(),
        }
    }
}

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

        let expected = ProtocolAdapter::Resource {
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

        let converted: ProtocolAdapter::Resource = aarm.into();

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

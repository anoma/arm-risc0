use alloy::sol;

use aarm::evm_adapter::{
    AdapterAction, AdapterComplianceUnit, AdapterLogicProof, AdapterTransaction,
};
use aarm_core::compliance::ComplianceInstance;
use aarm_core::logic_instance::{ExpirableBlob, LogicInstance};
use aarm_core::resource::Resource;
use alloy::primitives::{B256, U256};

sol!(
    #[allow(missing_docs)]
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
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
            actionTreeRoot: B256::from_slice(instance.root.as_bytes()),
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

impl From<ComplianceInstance> for ProtocolAdapter::ComplianceInstance {
    fn from(instance: ComplianceInstance) -> Self {
        Self {
            consumed: ProtocolAdapter::ConsumedRefs {
                nullifier: B256::from_slice(instance.consumed_nullifier.as_bytes()),
                logicRef: B256::from_slice(instance.consumed_logic_ref.as_bytes()),
                commitmentTreeRoot: B256::from_slice(
                    instance.consumed_commitment_tree_root.as_bytes(),
                ),
            },
            created: ProtocolAdapter::CreatedRefs {
                commitment: B256::from_slice(instance.created_commitment.as_bytes()),
                logicRef: B256::from_slice(instance.created_logic_ref.as_bytes()),
            },
            unitDeltaX: B256::from_slice(instance.delta_x.as_bytes()),
            unitDeltaY: B256::from_slice(instance.delta_y.as_bytes()),
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
    use alloy::primitives::Uint;
    use alloy::sol_types::SolValue;

    fn example_arm_resource(
        logic_ref: &[u8; 32],
        label_ref: &[u8; 32],
        value_ref: &[u8; 32],
        nkc: &[u8; 32],
        quantity: u128,
        nonce: Uint<256, 4>,
        rand_seed: Uint<256, 4>,
        ephemeral: bool,
    ) -> Resource {
        Resource {
            logic_ref: (*logic_ref).into(),
            label_ref: (*label_ref).into(),
            value_ref: (*value_ref).into(),
            nk_commitment: NullifierKeyCommitment::from_bytes((*nkc).into()),
            quantity,
            nonce: nonce.to_le_bytes(),
            rand_seed: rand_seed.to_le_bytes(),
            is_ephemeral: ephemeral,
        }
    }
    fn example_evm_resource(
        logic_ref: &[u8; 32],
        label_ref: &[u8; 32],
        value_ref: &[u8; 32],
        nkc: &[u8; 32],
        quantity: u128,
        nonce: Uint<256, 4>,
        rand_seed: Uint<256, 4>,
        ephemeral: bool,
    ) -> ProtocolAdapter::Resource {
        ProtocolAdapter::Resource {
            logicRef: B256::from_slice(logic_ref),
            labelRef: B256::from_slice(label_ref),
            valueRef: B256::from_slice(value_ref),
            nullifierKeyCommitment: B256::from_slice(nkc),
            quantity: U256::from(quantity),
            nonce,
            randSeed: rand_seed,
            ephemeral,
        }
    }

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

        assert_eq!(
            ProtocolAdapter::Resource::from(example_arm_resource(
                logic_ref, label_ref, value_ref, nkc, quantity, nonce, rand_seed, ephemeral,
            )),
            example_evm_resource(
                logic_ref, label_ref, value_ref, nkc, quantity, nonce, rand_seed, ephemeral,
            )
        );
    }

    #[test]
    fn print_resource() {
        println!(
            "{:?}",
            example_evm_resource(
                &[0x11; 32],
                &[0x22; 32],
                &[0x33; 32],
                &[0x44; 32],
                55,
                U256::from(66),
                U256::from(77),
                true,
            )
        )
    }

    fn vec_u8_to_hex_string(arr: &Vec<u8>) -> String {
        arr.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    }

    #[test]
    fn difference() {
        let raw_tx = aarm::transaction::generate_test_transaction(1);

        let raw_journal_bytes = raw_tx.action[0].compliance_units[0].journal.bytes.clone();

        // 8908b8d4641b053566380a6b900c07a1c6634ba1992bcedc30cc4f1e586b95f8b3efbbc411861566d8a690717f3beb93b6496b3f4d6659f6c0237713508a8a867e70786b1d52fc0412d75203ef2ac22de13d9596ace8a5a1ed5324c3ed7f31c3676f9cd10e72f99d2416ecc268dd7a6a2e5613085d471bd62d2685f977c7b55db3efbbc411861566d8a690717f3beb93b6496b3f4d6659f6c0237713508a8a8679000000be000000660000007e000000f9000000dc000000bb000000ac00000055000000a00000006200000095000000ce000000870000000b00000007000000020000009b000000fc000000db0000002d000000ce00000028000000d900000059000000f2000000810000005b00000016000000f80000001700000098000000480000003a000000da0000007700000026000000a3000000c4000000650000005d000000a4000000fb000000fc0000000e0000001100000008000000a8000000fd00000017000000b400000048000000a60000008500000054000000190000009c00000047000000d00000008f000000fb00000010000000d4000000b8000000
        println!(
            "Raw journal bytes:\n{:?}",
            vec_u8_to_hex_string(&raw_journal_bytes)
        );

        let raw_journal_decoded: ComplianceInstance = raw_tx.action[0].compliance_units[0]
            .journal
            .decode()
            .unwrap();
        println!("Raw journal decoded:\n{:?}", raw_journal_decoded);

        let instance_bincode_encoded = bincode::serialize(&raw_journal_decoded).unwrap();
        println!(
            "Instance_bincode_encoded:\n{:?}",
            vec_u8_to_hex_string(&instance_bincode_encoded)
        );

        let solidity_ref = "9f39696c27416c218ea0af1e862af2bc719e6f235c287368e27eaf6685ac4826943e3d1201c603a7bbb42a9af31456fe5da8250ede2cad1f225b237f465293978469baf624f97e8ee38f610200326e34c7a15de612b4107f772c6629dd5913199acc2b1c1164cb7830e3a770cdf5d4e7d1e68927d4b06b1799edac2d706484589b55dc162140c5dde2082e8319584739cb55870cd8456e958d3fb94b22790f3bdf2e4bb8057c9fd6ad79bfeb8e043692a95aa0b5d9c8efcd089cf642e5e5363e9b971e3000ee7647ec367bf531ba36254750fd6711902aca792f72aeeb7114fcc79afdc617a09665a8d7f57ae76a2d658fb8d9f66cbc427b7c75576850369635f242be71";
        println!(
            "Solidity reference `abi.encode(cu.instance)`:\n{:?}",
            solidity_ref
        );
    }

    #[test]
    fn print_instance_encodings() {
        let raw_tx = aarm::transaction::generate_test_transaction(1);

        println!(
            "Raw journal:\n{:?}",
            raw_tx.action[0].compliance_units[0]
                .journal
                .bytes
                .iter()
                .map(|b| format!("{:02x}", *b))
                .collect::<String>()
        );
        let raw_instance: ComplianceInstance = raw_tx.action[0].compliance_units[0]
            .journal
            .decode()
            .unwrap();

        println!("Raw instance decoded:\n{:?}", raw_instance);

        let raw_instance_encoded = bincode::serialize(&raw_instance).unwrap();
        println!(
            "Bincode encoded instance:\n{:?}",
            raw_instance_encoded
                .iter()
                .map(|b| format!("{:02x}", *b))
                .collect::<String>()
        );

        let adapter_tx = raw_tx.convert();

        let raw_adatper_instance = adapter_tx.actions[0].compliance_units[0].instance.clone();

        println!("Raw adapter instance:\n{:?}", raw_adatper_instance);

        let raw_adapter_instance_encoded = bincode::serialize(&raw_adatper_instance).unwrap();
        println!(
            "Bincode encoded adapter instance:\n{:?}",
            raw_adapter_instance_encoded
                .iter()
                .map(|b| format!("{:02x}", *b))
                .collect::<String>()
        );

        let evm_tx = ProtocolAdapter::Transaction::from(adapter_tx);
        let evm_instance = evm_tx.actions[0].complianceUnits[0].instance.clone();

        println!("EVM CU:\n{:?}", evm_tx.actions[0].complianceUnits[0]);

        println!(
            "EVM instance encoded:\n{:?}",
            evm_instance
                .abi_encode()
                .iter()
                .map(|b| format!("{:02x}", *b))
                .collect::<String>()
        );

        println!(
            "EVM instance encoded packed:\n{:?}",
            evm_instance
                .abi_encode_packed()
                .iter()
                .map(|b| format!("{:02x}", *b))
                .collect::<String>()
        );
    }

    #[test]
    fn print_tx() {
        let raw_tx = aarm::transaction::generate_test_transaction(1);
        let evm_tx = ProtocolAdapter::Transaction::from(raw_tx.convert());
        println!("EVM Tx:\n{:#?}", evm_tx);
    }
}

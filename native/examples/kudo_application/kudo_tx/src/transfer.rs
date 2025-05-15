use aarm::{
    action::Action,
    logic_proof::{LogicProof, LogicProver, PaddingResourceLogic},
    transaction::{Delta, Transaction},
    utils::groth16_prove,
};
use aarm_core::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey},
    compliance::ComplianceWitness,
    constants::COMMITMENT_TREE_DEPTH,
    delta_proof::DeltaWitness,
    merkle_path::MerklePath,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
};
use compliance_circuit::COMPLIANCE_GUEST_ELF;
use denomination_logic::{DENOMINATION_ELF, DENOMINATION_ID};
use kudo_core::{
    denomination_logic_witness::DenominationLogicWitness,
    kudo_logic_witness::KudoLogicWitness,
    receive_logic_witness::ReceiveLogicWitness,
    utils::{compute_kudo_label, compute_kudo_value},
};
use kudo_logic::{KUDO_LOGIC_ELF, KUDO_LOGIC_ID};
use receive_logic::{RECEIVE_ELF, RECEIVE_ID};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct TransferWitness {
    consumed_kudo_witness: KudoLogicWitness, // consumed resource - compliance unit 1
    consumed_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    consumed_denomination_witness: DenominationLogicWitness, // created resource - compliance unit 1
    created_kudo_witness: KudoLogicWitness,                  // created resource - compliance unit 2
    created_denomination_witness: DenominationLogicWitness, // consumed resource - compliance unit 2
    receive_witness: ReceiveLogicWitness,                   // created resource - compliance unit 3
    padding_resource_logic: PaddingResourceLogic,           // consumed resource - compliance unit 3
}

impl TransferWitness {
    pub fn build(
        issuer: &AuthorizationVerifyingKey,
        owner_sk: &AuthorizationSigningKey,
        consumed_kudo_resource: &Resource,
        consumed_kudo_nf_key: &NullifierKey,
        consumed_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
        receiver_pk: &AuthorizationVerifyingKey,
        receiver_signature: &AuthorizationSignature,
        receiver_nk_commitment: &NullifierKeyCommitment,
    ) -> Self {
        let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

        // Construct the consumed kudo resource
        let kudo_lable = compute_kudo_label(&DENOMINATION_ID.into(), issuer);
        assert_eq!(consumed_kudo_resource.label_ref, kudo_lable);
        let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
        let kudo_value = compute_kudo_value(&owner);
        assert_eq!(kudo_value, consumed_kudo_resource.value_ref);
        let consumed_kudo_nf = consumed_kudo_resource
            .nullifier(consumed_kudo_nf_key)
            .unwrap();

        // Construct the denomination resource corresponding to the consumed kudo resource
        let consumed_denomination_resource = Resource::create(
            DENOMINATION_ID.into(),
            Digest::default(), // TODO: fix the label?
            0,
            Digest::default(),
            true,
            instant_nk_commitment,
        );
        let consumed_denomination_resource_cm = consumed_denomination_resource.commitment();

        // Construct the created kudo resource
        let mut created_kudo_resource = consumed_kudo_resource.clone();
        // Set the new ownership to the created kudo resource
        created_kudo_resource.set_nf_commitment(*receiver_nk_commitment);
        let created_kudo_value = compute_kudo_value(receiver_pk);
        created_kudo_resource.set_value_ref(created_kudo_value);
        // Reset the randomness and nonce
        created_kudo_resource.reset_randomness_nonce();
        let created_kudo_value_cm = created_kudo_resource.commitment();

        // Construct the denomination resource corresponding to the created kudo resource
        let created_denomination_resource = Resource::create(
            DENOMINATION_ID.into(),
            Digest::default(), // TODO: fix the label?
            0,
            Digest::default(),
            true,
            instant_nk_commitment,
        );
        let created_denomination_resource_nf = created_denomination_resource
            .nullifier(&instant_nk)
            .unwrap();

        // Construct the receive logic resource
        let receive_resource = Resource::create(
            RECEIVE_ID.into(),
            created_kudo_value_cm,
            0,
            Digest::default(),
            true,
            instant_nk_commitment,
        );
        let receive_resource_cm = receive_resource.commitment();

        // Construct the padding resource
        let padding_resource = PaddingResourceLogic::create_padding_resource(instant_nk_commitment);
        let padding_resource_nf = padding_resource.nullifier(&instant_nk).unwrap();

        // Construct the action tree
        let action_tree = MerkleTree::new(vec![
            consumed_kudo_nf,
            consumed_denomination_resource_cm,
            created_denomination_resource_nf,
            created_kudo_value_cm,
            padding_resource_nf,
            receive_resource_cm,
        ]);
        let root = action_tree.root();

        // Generate paths
        let consumed_kudo_existence_path = action_tree.generate_path(consumed_kudo_nf).unwrap();
        let consumed_denomination_existence_path = action_tree
            .generate_path(consumed_denomination_resource_cm)
            .unwrap();
        let created_denomination_existence_path = action_tree
            .generate_path(created_denomination_resource_nf)
            .unwrap();
        let created_kudo_existence_path = action_tree.generate_path(created_kudo_value_cm).unwrap();
        let padding_resource_existence_path =
            action_tree.generate_path(padding_resource_nf).unwrap();
        let receive_existence_path = action_tree.generate_path(receive_resource_cm).unwrap();

        // Construct the consumed kudo witness
        let consumed_kudo_witness =
            KudoLogicWitness::generate_persistent_resource_consumption_witness(
                *consumed_kudo_resource,
                consumed_kudo_existence_path,
                *consumed_kudo_nf_key,
                *issuer,
                consumed_denomination_resource,
                consumed_denomination_existence_path,
                false,
            );

        // Construct the denomination witness corresponding to the consumed kudo resource
        let consumption_signature = owner_sk.sign(root.as_bytes());
        let consumed_denomination_witness =
            DenominationLogicWitness::generate_persistent_resource_consumption_witness(
                consumed_denomination_resource,
                consumed_denomination_existence_path,
                consumption_signature,
                *consumed_kudo_resource,
                consumed_kudo_existence_path,
                *consumed_kudo_nf_key,
                *issuer,
                owner,
            );

        // Construct the created kudo witness
        let created_kudo_witness = KudoLogicWitness::generate_persistent_resource_creation_witness(
            created_kudo_resource.clone(),
            created_kudo_existence_path,
            *issuer,
            created_denomination_resource,
            created_denomination_existence_path,
            instant_nk,
            true,
            receive_resource,
            instant_nk,
            false,
            receive_existence_path,
            *receiver_pk,
            *receiver_signature,
        );

        // Construct the denomination witness corresponding to the created kudo resource
        let created_denomination_witness =
            DenominationLogicWitness::generate_persistent_resource_creation_witness(
                created_denomination_resource,
                created_denomination_existence_path,
                true,
                instant_nk,
                created_kudo_resource,
                created_kudo_existence_path,
                *issuer,
            );

        // Construct the receive witness
        let receive_witness = ReceiveLogicWitness::generate_witness(
            receive_resource,
            receive_existence_path,
            instant_nk,
            false,
            created_kudo_resource,
            created_kudo_existence_path,
        );

        // Construct the padding logic witness
        let padding_resource_logic = PaddingResourceLogic::new(
            padding_resource,
            padding_resource_existence_path,
            instant_nk,
            true,
        );

        Self {
            consumed_kudo_witness,
            consumed_denomination_witness,
            created_kudo_witness,
            created_denomination_witness,
            padding_resource_logic,
            receive_witness,
            consumed_kudo_path,
        }
    }

    pub fn create_tx(&self) -> Transaction {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units Compliance unit 1: the consumed kudo
            // resource and the consumed denomination resource

            println!("Generating compliance unit 1");
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources_with_path(
                        self.consumed_kudo_witness.kudo_resource,
                        self.consumed_kudo_witness.kudo_nf_key,
                        self.consumed_kudo_path,
                        self.consumed_denomination_witness.denomination_resource,
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 2: the created kudo resource and the created
            // denomination resource
            println!("Generating compliance unit 2");
            let (compliance_unit_2, delta_witness_2) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.created_denomination_witness.denomination_resource,
                        self.created_denomination_witness.denomination_nf_key,
                        self.created_kudo_witness.kudo_resource,
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 3: the receive loigc resource and the padding
            // resource
            println!("Generating compliance unit 3");
            let (compliance_unit_3, delta_witness_3) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.padding_resource_logic.witness().resource,
                        self.padding_resource_logic.witness().nf_key,
                        self.receive_witness.receive_resource,
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the consumed kudo logic proof");
            let consumed_kudo_proof = {
                let receipt = groth16_prove(&self.consumed_kudo_witness, KUDO_LOGIC_ELF);
                LogicProof {
                    receipt,
                    verifying_key: KUDO_LOGIC_ID.into(),
                }
            };

            println!(
                "Generating the denomination logic proof corresponding to the consumed kudo resource"
            );
            let consumed_denomination_proof = {
                let receipt = groth16_prove(&self.consumed_denomination_witness, DENOMINATION_ELF);
                LogicProof {
                    receipt,
                    verifying_key: DENOMINATION_ID.into(),
                }
            };

            println!("Generating the created kudo logic proof");
            let created_kudo_proof = {
                let receipt = groth16_prove(&self.created_kudo_witness, KUDO_LOGIC_ELF);
                LogicProof {
                    receipt,
                    verifying_key: KUDO_LOGIC_ID.into(),
                }
            };

            println!("Generating the denomination logic proof corresponding to the created kudo resource");
            let created_denomination_proof = {
                let receipt = groth16_prove(&self.created_denomination_witness, DENOMINATION_ELF);
                LogicProof {
                    receipt,
                    verifying_key: DENOMINATION_ID.into(),
                }
            };

            println!("Generating the padding resource logic proof");
            let padding_resource_proof = self.padding_resource_logic.prove();

            println!("Generating the receive logic proof");
            let receive_logic_proof = {
                let receipt = groth16_prove(&self.receive_witness, RECEIVE_ELF);
                LogicProof {
                    receipt,
                    verifying_key: RECEIVE_ID.into(),
                }
            };

            (
                Action::new(
                    vec![compliance_unit_1, compliance_unit_2, compliance_unit_3],
                    vec![
                        consumed_kudo_proof,
                        consumed_denomination_proof,
                        created_kudo_proof,
                        created_denomination_proof,
                        padding_resource_proof,
                        receive_logic_proof,
                    ],
                ),
                DeltaWitness::from_scalars(&[delta_witness_1, delta_witness_2, delta_witness_3]),
            )
        };

        // Create the transaction
        Transaction::new(vec![action], Delta::Witness(delta_witness))
    }
}

#[test]
fn generate_a_transfer_tx() {
    use kudo_core::utils::generate_receive_signature;

    let issuer_sk = AuthorizationSigningKey::new();
    let issuer = AuthorizationVerifyingKey::from_signing_key(&issuer_sk);
    let kudo_lable = compute_kudo_label(&DENOMINATION_ID.into(), &issuer);
    let owner_sk = AuthorizationSigningKey::new();
    let owner = AuthorizationVerifyingKey::from_signing_key(&owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    let (kudo_nf_key, kudo_nk_cm) = NullifierKey::random_pair();

    let (receiver_pk, receiver_signature) = {
        let sk = AuthorizationSigningKey::new();
        let pk = AuthorizationVerifyingKey::from_signing_key(&sk);
        let signature = generate_receive_signature(&Digest::new(RECEIVE_ID), &sk);
        (pk, signature)
    };
    let (_receiver_nf_key, receiver_nk_commitment) = NullifierKey::random_pair();

    let consumed_kudo_resource = Resource::create(
        KUDO_LOGIC_ID.into(),
        kudo_lable,
        100,
        kudo_value,
        false,
        kudo_nk_cm,
    );

    let transfer_witness = TransferWitness::build(
        &issuer,
        &owner_sk,
        &consumed_kudo_resource,
        &kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
        &receiver_pk,
        &receiver_signature,
        &receiver_nk_commitment,
    );

    let mut tx = transfer_witness.create_tx();
    tx.generate_delta_proof();

    assert!(tx.verify());
}

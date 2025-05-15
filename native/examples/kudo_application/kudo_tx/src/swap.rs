use aarm::{
    action::{Action, LogicProof},
    transaction::{Delta, Transaction},
    utils::groth16_prove,
};
use aarm_core::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSigningKey, AuthorizationVerifyingKey},
    compliance::ComplianceWitness,
    constants::COMMITMENT_TREE_DEPTH,
    delta_proof::DeltaWitness,
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
    trivial_logic::TrivialLogicWitness,
};
use compliance_circuit::COMPLIANCE_GUEST_ELF;
use denomination_logic::{DENOMINATION_ELF, DENOMINATION_ID};
use kudo_core::{
    denomination_logic_witness::DenominationLogicWitness,
    kudo_logic_witness::KudoLogicWitness,
    receive_logic_witness::ReceiveLogicWitness,
    utils::{compute_kudo_label, compute_kudo_value, generate_receive_signature},
};
use kudo_logic::{KUDO_LOGIC_ELF, KUDO_LOGIC_ID};
use receive_logic::{RECEIVE_ELF, RECEIVE_ID};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};
use trivial_logic::{TRIVIAL_ELF, TRIVIAL_ID};

// TODO: SwapWitness seems simillar to TransferWitness, consider abstracting and
// merging them
#[derive(Clone, Serialize, Deserialize)]
pub struct SwapWitness {
    consumed_kudo_witness: KudoLogicWitness, // consumed resource - compliance unit 1
    consumed_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    consumed_denomination_witness: DenominationLogicWitness, // created resource - compliance unit 1
    created_kudo_witness: KudoLogicWitness,                  // created resource - compliance unit 2
    created_denomination_witness: DenominationLogicWitness, // consumed resource - compliance unit 2
    receive_witness: ReceiveLogicWitness,                   // created resource - compliance unit 3
    padding_resource_witness: TrivialLogicWitness,          // consumed resource - compliance unit 3
}

impl SwapWitness {
    pub fn build(
        consumed_issuer: &AuthorizationVerifyingKey,
        owner_sk: &AuthorizationSigningKey,
        consumed_kudo_resource: &Resource,
        nf_key: &NullifierKey,
        consumed_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
        created_issuer: &AuthorizationVerifyingKey,
        created_kudo_quantity: u128,
    ) -> Self {
        let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

        // Construct the consumed kudo resource
        let consumed_kudo_lable = compute_kudo_label(&DENOMINATION_ID.into(), consumed_issuer);
        assert_eq!(consumed_kudo_resource.label_ref, consumed_kudo_lable);
        let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
        let kudo_value = compute_kudo_value(&owner);
        assert_eq!(kudo_value, consumed_kudo_resource.value_ref);
        let consumed_kudo_nf = consumed_kudo_resource.nullifier(nf_key).unwrap();

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

        // Construct the created kudo resource: same ownership(kudo_value and
        // nk_commitment) as the consumed kudo resource
        let created_kudo_lable = compute_kudo_label(&DENOMINATION_ID.into(), created_issuer);
        let created_kudo_resource = Resource::create(
            KUDO_LOGIC_ID.into(),
            created_kudo_lable,
            created_kudo_quantity,
            kudo_value, // use the same kudo value as the consumed kudo resource
            false,
            consumed_kudo_resource.nk_commitment, // use the same nk_commitment as the consumed kudo resource
        );
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
        let padding_resource = TrivialLogicWitness::create_trivial_resource(instant_nk_commitment);
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
                *nf_key,
                *consumed_issuer,
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
                *nf_key,
                *consumed_issuer,
                owner,
            );

        // Construct the created kudo witness
        let receiver_signature = generate_receive_signature(&Digest::new(RECEIVE_ID), &owner_sk);
        let created_kudo_witness = KudoLogicWitness::generate_persistent_resource_creation_witness(
            created_kudo_resource.clone(),
            created_kudo_existence_path,
            *created_issuer,
            created_denomination_resource,
            created_denomination_existence_path,
            instant_nk,
            true,
            receive_resource,
            instant_nk,
            false,
            receive_existence_path,
            owner,
            receiver_signature,
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
                *created_issuer,
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
        let padding_resource_witness = TrivialLogicWitness::generate_witness(
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
            padding_resource_witness,
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
                        self.padding_resource_witness.resource,
                        self.padding_resource_witness.nf_key,
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
            let padding_resource_proof = {
                let receipt = groth16_prove(&self.padding_resource_witness, TRIVIAL_ELF);
                LogicProof {
                    receipt,
                    verifying_key: TRIVIAL_ID.into(),
                }
            };

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
fn generate_a_swap_tx() {
    // The issuer determines the kind of kudo
    let alice_consumed_issuer_sk = AuthorizationSigningKey::new();
    let alice_consumed_issuer =
        AuthorizationVerifyingKey::from_signing_key(&alice_consumed_issuer_sk);
    let alice_consumed_kudo_lable =
        compute_kudo_label(&DENOMINATION_ID.into(), &alice_consumed_issuer);

    // The consumed and created kudo resources share the same ownership(value and nk)
    let alice_sk = AuthorizationSigningKey::new();
    let alice_pk = AuthorizationVerifyingKey::from_signing_key(&alice_sk);
    let alice_kudo_value = compute_kudo_value(&alice_pk);
    let (alice_kudo_nf_key, alice_kudo_nk_cm) = NullifierKey::random_pair();
    let alice_consumed_kudo_quantity = 100;

    let alice_consumed_kudo_resource = Resource::create(
        KUDO_LOGIC_ID.into(),
        alice_consumed_kudo_lable,
        alice_consumed_kudo_quantity,
        alice_kudo_value,
        false,
        alice_kudo_nk_cm,
    );

    let alice_created_issuer_sk = AuthorizationSigningKey::new();
    let alice_created_issuer =
        AuthorizationVerifyingKey::from_signing_key(&alice_created_issuer_sk);
    let alice_created_kudo_lable =
        compute_kudo_label(&DENOMINATION_ID.into(), &alice_created_issuer);
    let alice_created_kudo_quantity = 200;

    let alice_swap_witness = SwapWitness::build(
        &alice_consumed_issuer,
        &alice_sk,
        &alice_consumed_kudo_resource,
        &alice_kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
        &alice_created_issuer,
        alice_created_kudo_quantity,
    );

    let alice_tx = alice_swap_witness.create_tx();

    let bob_sk = AuthorizationSigningKey::new();
    let bob_pk = AuthorizationVerifyingKey::from_signing_key(&bob_sk);
    let bob_kudo_value = compute_kudo_value(&bob_pk);
    let (bob_kudo_nf_key, bob_kudo_nk_cm) = NullifierKey::random_pair();
    let bob_consumed_kudo_resource = Resource::create(
        KUDO_LOGIC_ID.into(),
        alice_created_kudo_lable,
        alice_created_kudo_quantity,
        bob_kudo_value,
        false,
        bob_kudo_nk_cm,
    );
    let bob_consumed_issuer = alice_created_issuer;
    let bob_created_issuer = alice_consumed_issuer;
    let bob_created_kudo_quantity = alice_consumed_kudo_quantity;
    let bob_swap_witness = SwapWitness::build(
        &bob_consumed_issuer,
        &bob_sk,
        &bob_consumed_kudo_resource,
        &bob_kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
        &bob_created_issuer,
        bob_created_kudo_quantity,
    );
    let bob_tx = bob_swap_witness.create_tx();

    let mut tx = Transaction::compose(alice_tx, bob_tx);
    tx.generate_delta_proof();
    assert!(tx.verify());
}

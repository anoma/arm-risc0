use aarm::{
    action::Action,
    logic_proof::LogicProof,
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
};
use compliance_circuit::COMPLIANCE_GUEST_ELF;
use denomination_logic::{DENOMINATION_ELF, DENOMINATION_ID};
use kudo_core::{
    denomination_logic_witness::DenominationLogicWitness,
    kudo_logic_witness::KudoLogicWitness,
    utils::{compute_kudo_label, compute_kudo_value},
};
use kudo_logic::{KUDO_LOGIC_ELF, KUDO_LOGIC_ID};
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct BurnWitness {
    burned_kudo_witness: KudoLogicWitness, // consumed resource
    burned_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    burned_denomination_witness: DenominationLogicWitness, // created resource
    ephemeral_kudo_witness: KudoLogicWitness,              // created resource
    ephemeral_denomination_witness: DenominationLogicWitness, // consumed resource
}

impl BurnWitness {
    pub fn build(
        issuer_sk: &AuthorizationSigningKey,
        owner_sk: &AuthorizationSigningKey,
        burned_kudo_resource: &Resource,
        burned_kudoresource_nf_key: &NullifierKey,
        burned_kudo_path: MerklePath<COMMITMENT_TREE_DEPTH>,
    ) -> Self {
        let issuer = AuthorizationVerifyingKey::from_signing_key(issuer_sk);
        let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

        // Construct the burned kudo resource
        let kudo_lable = compute_kudo_label(&DENOMINATION_ID.into(), &issuer);
        assert_eq!(burned_kudo_resource.label_ref, kudo_lable);
        let owner = AuthorizationVerifyingKey::from_signing_key(owner_sk);
        let kudo_value = compute_kudo_value(&owner);
        assert_eq!(kudo_value, burned_kudo_resource.value_ref);
        let burned_kudo_resource_nf = burned_kudo_resource
            .nullifier(burned_kudoresource_nf_key)
            .unwrap();

        // Construct the burned denomination resource
        let burned_denomination_resource = Resource::create(
            DENOMINATION_ID.into(),
            Digest::default(), // TODO: fix the label?
            0,
            Digest::default(),
            true,
            instant_nk_commitment,
        );
        let burned_denomination_resource_cm = burned_denomination_resource.commitment();

        // Construct the ephemeral kudo resource
        let mut ephemeral_kudo_resource = burned_kudo_resource.clone();
        ephemeral_kudo_resource.is_ephemeral = true;
        let ephemeral_kudo_resource_cm = ephemeral_kudo_resource.commitment();

        // Construct the ephemeral denomination resource
        let ephemeral_denomination_resource = Resource::create(
            DENOMINATION_ID.into(),
            Digest::default(), // TODO: fix the label?
            0,
            Digest::default(),
            true,
            instant_nk_commitment,
        );
        let ephemeral_denomination_resource_nf = ephemeral_denomination_resource
            .nullifier(&instant_nk)
            .unwrap();

        // Construct the action tree
        let action_tree = MerkleTree::new(vec![
            burned_kudo_resource_nf,
            burned_denomination_resource_cm,
            ephemeral_denomination_resource_nf,
            ephemeral_kudo_resource_cm,
        ]);
        let root = action_tree.root();

        // Generate paths
        let burned_kudo_existence_path =
            action_tree.generate_path(burned_kudo_resource_nf).unwrap();
        let burned_denomination_existence_path = action_tree
            .generate_path(burned_denomination_resource_cm)
            .unwrap();
        let ephemeral_denomination_existence_path = action_tree
            .generate_path(ephemeral_denomination_resource_nf)
            .unwrap();
        let ephemeral_kudo_existence_path = action_tree
            .generate_path(ephemeral_kudo_resource_cm)
            .unwrap();

        // Construct the burned kudo witness: consume the kudo resource
        let burned_kudo_witness =
            KudoLogicWitness::generate_persistent_resource_consumption_witness(
                *burned_kudo_resource,
                burned_kudo_existence_path,
                *burned_kudoresource_nf_key,
                issuer,
                burned_denomination_resource,
                burned_denomination_existence_path,
                false,
            );

        // Construct the denomination witness corresponding to the consumed kudo resource
        let consumption_signature = owner_sk.sign(root.as_bytes());
        let burned_denomination_witness =
            DenominationLogicWitness::generate_persistent_resource_consumption_witness(
                burned_denomination_resource,
                burned_denomination_existence_path,
                consumption_signature,
                *burned_kudo_resource,
                burned_kudo_existence_path,
                *burned_kudoresource_nf_key,
                issuer,
                owner,
            );

        // Construct the ephemeral kudo witness
        let ephemeral_kudo_witness = KudoLogicWitness::generate_created_ephemeral_witness(
            ephemeral_kudo_resource.clone(),
            ephemeral_kudo_existence_path,
            issuer,
            ephemeral_denomination_resource,
            ephemeral_denomination_existence_path,
            instant_nk,
        );

        // Construct the denomination witness, corresponding to the ephemeral kudo resource
        let burn_signature = issuer_sk.sign(root.as_bytes());
        let ephemeral_denomination_witness =
            DenominationLogicWitness::generate_burned_ephemeral_witness(
                ephemeral_denomination_resource,
                ephemeral_denomination_existence_path,
                instant_nk,
                burn_signature,
                ephemeral_kudo_resource.clone(),
                ephemeral_kudo_existence_path,
                issuer,
                owner,
            );

        Self {
            burned_kudo_witness,
            burned_denomination_witness,
            ephemeral_kudo_witness,
            ephemeral_denomination_witness,
            burned_kudo_path,
        }
    }

    pub fn create_tx(&self) -> Transaction {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units
            // Compliance unit 1: the ephemeral_kudo_resource and the issued_kudo_resource

            println!("Generating compliance unit 1");
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources_with_path(
                        self.burned_kudo_witness.kudo_resource,
                        self.burned_kudo_witness.kudo_nf_key,
                        self.burned_kudo_path,
                        self.burned_denomination_witness.denomination_resource,
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 2: the issued_receive_resource and the issued_denomination_resource
            println!("Generating compliance unit 2");
            let (compliance_unit_2, delta_witness_2) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.ephemeral_denomination_witness.denomination_resource,
                        self.ephemeral_denomination_witness.denomination_nf_key,
                        self.ephemeral_kudo_witness.denomination_resource,
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the burned kudo logic proof");
            let burned_kudo_proof = {
                let receipt = groth16_prove(&self.burned_kudo_witness, KUDO_LOGIC_ELF);
                LogicProof {
                    receipt,
                    verifying_key: KUDO_LOGIC_ID.into(),
                }
            };

            println!(
                "Generating the denomination logic proof corresponding to the burned kudo resource"
            );
            let burned_denomination_proof = {
                let receipt = groth16_prove(&self.burned_denomination_witness, DENOMINATION_ELF);
                LogicProof {
                    receipt,
                    verifying_key: DENOMINATION_ID.into(),
                }
            };

            println!("Generating the ephemeral kudo logic proof");
            let ephemeral_kudo_proof = {
                let receipt = groth16_prove(&self.ephemeral_kudo_witness, KUDO_LOGIC_ELF);
                LogicProof {
                    receipt,
                    verifying_key: KUDO_LOGIC_ID.into(),
                }
            };

            println!("Generating the denomination logic proof corresponding to the ephemeral kudo resource");
            let ephemeral_denomination_proof = {
                let receipt = groth16_prove(&self.ephemeral_denomination_witness, DENOMINATION_ELF);
                LogicProof {
                    receipt,
                    verifying_key: DENOMINATION_ID.into(),
                }
            };

            (
                Action::new(
                    vec![compliance_unit_1, compliance_unit_2],
                    vec![
                        burned_kudo_proof,
                        burned_denomination_proof,
                        ephemeral_kudo_proof,
                        ephemeral_denomination_proof,
                    ],
                ),
                DeltaWitness::from_scalars(&[delta_witness_1, delta_witness_2]),
            )
        };

        // Create the transaction
        Transaction::new(vec![action], Delta::Witness(delta_witness))
    }
}

#[test]
fn generate_a_burn_tx() {
    let issuer_sk = AuthorizationSigningKey::new();
    let issuer = AuthorizationVerifyingKey::from_signing_key(&issuer_sk);
    let kudo_lable = compute_kudo_label(&DENOMINATION_ID.into(), &issuer);
    let owner_sk = issuer_sk.clone();
    let owner = AuthorizationVerifyingKey::from_signing_key(&owner_sk);
    let kudo_value = compute_kudo_value(&owner);
    let (kudo_nf_key, kudo_nk_cm) = NullifierKey::random_pair();

    let kudo_resource = Resource::create(
        KUDO_LOGIC_ID.into(),
        kudo_lable,
        100,
        kudo_value,
        false,
        kudo_nk_cm,
    );

    let burn_witness = BurnWitness::build(
        &issuer_sk,
        &owner_sk,
        &kudo_resource,
        &kudo_nf_key,
        MerklePath::<COMMITMENT_TREE_DEPTH>::default(), // It should be a real path
    );

    let mut tx = burn_witness.create_tx();
    tx.generate_delta_proof();

    assert!(tx.verify());
}

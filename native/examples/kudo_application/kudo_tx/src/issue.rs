use aarm::{
    action::Action,
    transaction::{Delta, Transaction},
};
use aarm_core::{
    action_tree::MerkleTree,
    authorization::{AuthorizationSignature, AuthorizationSigningKey, AuthorizationVerifyingKey},
    compliance::ComplianceWitness,
    delta_proof::DeltaWitness,
    nullifier_key::{NullifierKey, NullifierKeyCommitment},
    resource::Resource,
    trivial_logic::TrivialLogicWitness,
};
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
use trivial_logic::TRIVIAL_ELF;

#[derive(Clone, Serialize, Deserialize)]
pub struct IssueWitness {
    issued_kudo_witness: KudoLogicWitness,
    issued_denomination_witness: DenominationLogicWitness,
    issued_receive_witness: ReceiveLogicWitness,
    ephemeral_kudo_witness: KudoLogicWitness,
    ephemeral_denomination_witness: DenominationLogicWitness,
    padding_resource_witness: TrivialLogicWitness,
}

impl IssueWitness {
    pub fn build(
        issuer_sk: &AuthorizationSigningKey,
        quantity: u128,
        receiver_pk: &AuthorizationVerifyingKey,
        receiver_signature: &AuthorizationSignature,
        receiver_nk_commitment: &NullifierKeyCommitment,
    ) -> Self {
        let issuer = AuthorizationVerifyingKey::from_signing_key(issuer_sk);
        let (instant_nk, instant_nk_commitment) = NullifierKey::random_pair();

        // Construct the issued kudo resource
        let kudo_lable = compute_kudo_label(&DENOMINATION_ID.into(), &issuer);
        let kudo_value = compute_kudo_value(receiver_pk);
        let issued_kudo_resource = Resource::create(
            KUDO_LOGIC_ID.into(),
            kudo_lable,
            quantity,
            kudo_value,
            false,
            *receiver_nk_commitment,
        );
        let issued_kudo_resource_cm = issued_kudo_resource.commitment();

        // Construct the ephemeral kudo resource
        let ephemeral_kudo_resource = Resource::create(
            KUDO_LOGIC_ID.into(),
            kudo_lable,
            quantity,
            kudo_value,
            true,
            instant_nk_commitment,
        );
        let ephemeral_kudo_resource_nf = ephemeral_kudo_resource.nullifier(&instant_nk).unwrap();

        // Construct the issued denomination resource
        let issued_denomination_resource = Resource::create(
            DENOMINATION_ID.into(),
            Digest::default(), // TODO: fix the label?
            0,
            Digest::default(),
            true,
            instant_nk_commitment,
        );
        let issued_denomination_resource_cm = issued_denomination_resource.commitment();

        // Construct the issued receive logic resource
        let issued_receive_resource = Resource::create(
            RECEIVE_ID.into(),
            issued_kudo_resource_cm,
            0,
            Digest::default(),
            true,
            instant_nk_commitment,
        );
        let issued_receive_resource_nf = issued_receive_resource.nullifier(&instant_nk).unwrap();

        // Construct the ephemeral denomination resource
        let ephemeral_denomination_resource = Resource::create(
            DENOMINATION_ID.into(),
            Digest::default(), // TODO: fix the label?
            0,
            Digest::default(),
            true,
            instant_nk_commitment,
        );
        let ephemeral_denomination_resource_cm = ephemeral_denomination_resource.commitment();

        // Construct the padding resource
        let padding_resource = TrivialLogicWitness::create_trivial_resource(instant_nk_commitment);
        let padding_resource_nf = padding_resource.nullifier(&instant_nk).unwrap();

        // Construct the action tree
        let action_tree = MerkleTree::new(vec![
            ephemeral_kudo_resource_nf,
            issued_kudo_resource_cm,
            issued_receive_resource_nf,
            issued_denomination_resource_cm,
            padding_resource_nf,
            ephemeral_denomination_resource_cm,
        ]);
        let root = action_tree.root();

        // Generate paths
        let ephemeral_kudo_existence_path = action_tree
            .generate_path(ephemeral_kudo_resource_nf)
            .unwrap();
        let issued_kudo_existence_path =
            action_tree.generate_path(issued_kudo_resource_cm).unwrap();
        let issued_receive_existence_path = action_tree
            .generate_path(issued_receive_resource_nf)
            .unwrap();
        let issued_denomination_existence_path = action_tree
            .generate_path(issued_denomination_resource_cm)
            .unwrap();
        let padding_resource_existence_path =
            action_tree.generate_path(padding_resource_nf).unwrap();
        let ephemeral_denomination_existence_path = action_tree
            .generate_path(ephemeral_denomination_resource_cm)
            .unwrap();

        // Construct the issued kudo witness
        let issued_kudo_witness = KudoLogicWitness::create_issued_persistent_witness(
            issued_kudo_resource,
            issued_kudo_existence_path,
            issuer,
            issued_denomination_resource,
            issued_denomination_existence_path,
            issued_receive_resource,
            instant_nk,
            issued_receive_existence_path,
            *receiver_pk,
            *receiver_signature,
        );

        // Construct the issued denomination witness
        let issued_denomination_witness =
            DenominationLogicWitness::create_issued_persistent_witness(
                issued_denomination_resource,
                issued_denomination_existence_path,
                issued_kudo_resource,
                issued_kudo_existence_path,
                issuer,
            );

        // Construct the issued receive witness
        let issued_receive_witness = ReceiveLogicWitness::create_issued_persistent_witness(
            issued_receive_resource,
            issued_receive_existence_path,
            instant_nk,
            issued_kudo_resource,
            issued_kudo_existence_path,
        );

        // Construct the ephemeral kudo witness
        let ephemeral_kudo_witness = KudoLogicWitness::create_consumed_ephemeral_witness(
            ephemeral_kudo_resource,
            ephemeral_kudo_existence_path,
            instant_nk,
            issuer,
            ephemeral_denomination_resource,
            ephemeral_denomination_existence_path,
        );

        // Construct the ephemeral denomination witness
        let signature = issuer_sk.sign(root.as_bytes());
        let ephemeral_denomination_witness =
            DenominationLogicWitness::create_issued_ephemeral_witness(
                ephemeral_denomination_resource,
                ephemeral_denomination_existence_path,
                signature,
                ephemeral_kudo_resource,
                ephemeral_kudo_existence_path,
                instant_nk,
                issuer,
            );

        // Construct the padding logic witness
        let padding_resource_witness = TrivialLogicWitness::create_witness(
            padding_resource,
            padding_resource_existence_path,
            instant_nk,
            true,
        );

        Self {
            issued_kudo_witness,
            issued_denomination_witness,
            issued_receive_witness,
            ephemeral_kudo_witness,
            ephemeral_denomination_witness,
            padding_resource_witness,
        }
    }

    pub fn create_tx(&self) -> Transaction {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units
            // Compliance unit 1: the ephemeral_kudo_resource and the issued_kudo_resource

            println!("Generating compliance unit 1");
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness = ComplianceWitness::from_resources(
                    self.ephemeral_kudo_witness.kudo_resource,
                    self.ephemeral_kudo_witness.nf_key,
                    self.issued_kudo_witness.kudo_resource,
                );

                (
                    generate_compliance_proof(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 2: the issued_receive_resource and the issued_denomination_resource
            println!("Generating compliance unit 2");
            let (compliance_unit_2, delta_witness_2) = {
                let compliance_witness = ComplianceWitness::from_resources(
                    self.issued_receive_witness.receive_resource,
                    self.issued_receive_witness.nf_key,
                    self.issued_denomination_witness.denomination_resource,
                );

                (
                    generate_compliance_proof(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 3: a padding resource and the ephemeral_denomination_resource
            println!("Generating compliance unit 3");
            let (compliance_unit_3, delta_witness_3) = {
                let compliance_witness = ComplianceWitness::from_resources(
                    self.padding_resource_witness.resource,
                    self.padding_resource_witness.nf_key,
                    self.ephemeral_denomination_witness.denomination_resource,
                );

                (
                    generate_compliance_proof(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the issued kudo logic proof");
            let issued_kudo_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.issued_kudo_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        KUDO_LOGIC_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            println!("Generating the issued denomination logic proof");
            let issued_denomination_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.issued_denomination_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        DENOMINATION_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            println!("Generating the issued receive logic proof");
            let issued_receive_logic_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.issued_receive_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        RECEIVE_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            println!("Generating the ephemeral kudo logic proof");
            let ephemeral_kudo_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.ephemeral_kudo_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        KUDO_LOGIC_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            println!("Generating the ephemeral denomination logic proof");
            let ephemeral_denomination_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.ephemeral_denomination_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        DENOMINATION_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            println!("Generating the padding resource logic proof");
            let padding_resource_receipt = {
                let env = ExecutorEnv::builder()
                    .write(&self.padding_resource_witness)
                    .unwrap()
                    .build()
                    .unwrap();
                default_prover()
                    .prove_with_ctx(
                        env,
                        &VerifierContext::default(),
                        TRIVIAL_ELF,
                        &ProverOpts::groth16(),
                    )
                    .unwrap()
                    .receipt
            };

            (
                Action::new(
                    vec![compliance_unit_1, compliance_unit_2, compliance_unit_3],
                    vec![
                        issued_kudo_receipt,
                        issued_denomination_receipt,
                        issued_receive_logic_receipt,
                        ephemeral_kudo_receipt,
                        ephemeral_denomination_receipt,
                        padding_resource_receipt,
                    ],
                ),
                DeltaWitness::from_scalars(&[delta_witness_1, delta_witness_2, delta_witness_3]),
            )
        };

        // Create the transaction
        Transaction::new(vec![action], Delta::Witness(delta_witness))
    }
}

// TODO: Move this to aarm
use aarm_core::constants::TREE_DEPTH;
use compliance_circuit::COMPLIANCE_GUEST_ELF;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt, VerifierContext};

fn generate_compliance_proof(witness: &ComplianceWitness<TREE_DEPTH>) -> Receipt {
    let env = ExecutorEnv::builder()
        .write(witness)
        .unwrap()
        .build()
        .unwrap();

    default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            COMPLIANCE_GUEST_ELF,
            &ProverOpts::groth16(),
        )
        .unwrap()
        .receipt
}

#[test]
fn generate_an_issue_tx() {
    let (receiver_pk, receiver_signature) = {
        let sk = AuthorizationSigningKey::new();
        let pk = AuthorizationVerifyingKey::from_signing_key(&sk);
        let mut msg = Vec::new();
        msg.extend_from_slice(Digest::new(RECEIVE_ID).as_bytes());
        msg.extend_from_slice(&pk.to_bytes());
        let signature = sk.sign(&msg);
        (pk, signature)
    };

    let issue_witness = IssueWitness::build(
        &AuthorizationSigningKey::new(),
        100,
        &receiver_pk,
        &receiver_signature,
        &NullifierKeyCommitment::default(),
    );

    let _tx = issue_witness.create_tx();
}

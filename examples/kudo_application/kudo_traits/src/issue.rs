use crate::resource_info::{DenominationInfo, KudoInfo, ReceiveInfo};
use aarm::{
    action::Action,
    compliance_unit::ComplianceUnit,
    logic_proof::{LogicProver, PaddingResourceLogic},
    transaction::{Delta, Transaction},
};
use aarm_core::{
    compliance::ComplianceWitness, constants::COMMITMENT_TREE_DEPTH, delta_proof::DeltaWitness,
};

#[derive(Clone)]
pub struct Issue<K, D, R>
where
    K: KudoInfo,
    D: DenominationInfo,
    R: ReceiveInfo,
{
    pub issue_kudo: K,
    pub issue_denomination: D,
    pub issue_receive: R,
    pub ephemeral_kudo: K,
    pub ephemeral_denomination: D,
    pub padding_resource_logic: PaddingResourceLogic,
}

impl<K, D, R> Issue<K, D, R>
where
    K: KudoInfo,
    D: DenominationInfo,
    R: ReceiveInfo,
{
    pub fn create_tx(&self) -> Transaction {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units
            // Compliance unit 1: the ephemeral_kudo_resource and the issued_kudo_resource

            println!("Generating compliance unit 1");
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.ephemeral_kudo.resource(),
                        self.ephemeral_kudo.nf_key().unwrap(),
                        self.issue_kudo.resource(),
                    );

                (
                    ComplianceUnit::prove(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 2: the issued_receive_resource and the issued_denomination_resource
            println!("Generating compliance unit 2");
            let (compliance_unit_2, delta_witness_2) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.issue_receive.resource(),
                        self.issue_receive.nf_key().unwrap(),
                        self.issue_denomination.resource(),
                    );

                (
                    ComplianceUnit::prove(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 3: a padding resource and the ephemeral_denomination_resource
            println!("Generating compliance unit 3");
            let (compliance_unit_3, delta_witness_3) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.padding_resource_logic.witness().resource.clone(),
                        self.padding_resource_logic.witness().nf_key.clone(),
                        self.ephemeral_denomination.resource(),
                    );

                (
                    ComplianceUnit::prove(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the issued kudo logic proof");
            let issued_kudo_proof = self.issue_kudo.prove();

            println!("Generating the issued denomination logic proof");
            let issue_denomination_proof = self.issue_denomination.prove();

            println!("Generating the issued receive logic proof");
            let issued_receive_logic_proof = self.issue_receive.prove();

            println!("Generating the ephemeral kudo logic proof");
            let ephemeral_kudo_proof = self.ephemeral_kudo.prove();

            println!("Generating the ephemeral denomination logic proof");
            let ephemeral_denomination_proof = self.ephemeral_denomination.prove();

            println!("Generating the padding resource logic proof");
            let padding_resource_proof = self.padding_resource_logic.prove();

            (
                Action::new(
                    vec![compliance_unit_1, compliance_unit_2, compliance_unit_3],
                    vec![
                        issued_kudo_proof,
                        issue_denomination_proof,
                        issued_receive_logic_proof,
                        ephemeral_kudo_proof,
                        ephemeral_denomination_proof,
                        padding_resource_proof,
                    ],
                    vec![],
                ),
                DeltaWitness::from_bytes_vec(&[delta_witness_1, delta_witness_2, delta_witness_3]),
            )
        };

        // Create the transaction
        Transaction::new(vec![action], Delta::Witness(delta_witness))
    }
}

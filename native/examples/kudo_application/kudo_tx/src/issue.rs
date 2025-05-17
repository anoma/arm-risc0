use aarm::{
    action::Action,
    logic_proof::{LogicProver, PaddingResourceLogic},
    transaction::{Delta, Transaction},
    utils::groth16_prove,
};
use aarm_core::{
    compliance::ComplianceWitness, constants::COMMITMENT_TREE_DEPTH, delta_proof::DeltaWitness,
};
use compliance_circuit::COMPLIANCE_GUEST_ELF;
use kudo_core::{denomination::Denomination, kudo::Kudo, receive::Receive};

#[derive(Clone)]
pub struct IssueInstance<K, D, R>
where
    K: Kudo + LogicProver,
    D: Denomination + LogicProver,
    R: Receive + LogicProver,
{
    pub issue_kudo: K,
    pub issue_denomination: D,
    pub issue_receive: R,
    pub ephemeral_kudo: K,
    pub ephemeral_denomination: D,
    pub padding_resource_logic: PaddingResourceLogic,
}

impl<K, D, R> IssueInstance<K, D, R>
where
    K: Kudo + LogicProver,
    D: Denomination + LogicProver,
    R: Receive + LogicProver,
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
                        self.ephemeral_kudo.nf_key(),
                        self.issue_kudo.resource(),
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
                        self.issue_receive.resource(),
                        self.issue_receive.nf_key(),
                        self.issue_denomination.resource(),
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 3: a padding resource and the ephemeral_denomination_resource
            println!("Generating compliance unit 3");
            let (compliance_unit_3, delta_witness_3) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.padding_resource_logic.witness().resource,
                        self.padding_resource_logic.witness().nf_key,
                        self.ephemeral_denomination.resource(),
                    );

                (
                    groth16_prove(&compliance_witness, COMPLIANCE_GUEST_ELF),
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
                ),
                DeltaWitness::from_scalars(&[delta_witness_1, delta_witness_2, delta_witness_3]),
            )
        };

        // Create the transaction
        Transaction::new(vec![action], Delta::Witness(delta_witness))
    }
}

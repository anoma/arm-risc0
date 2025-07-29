use crate::resource_info::{DenominationInfo, KudoInfo, ReceiveInfo};
use arm::{
    action::Action,
    compliance_unit::ComplianceUnit,
    logic_proof::{LogicProver, PaddingResourceLogic},
    transaction::{Delta, Transaction},
};
use arm::{
    compliance::ComplianceWitness, delta_proof::DeltaWitness, merkle_path::COMMITMENT_TREE_DEPTH,
};

#[derive(Clone)]
pub struct Transfer<K, D, R>
where
    K: KudoInfo,
    D: DenominationInfo,
    R: ReceiveInfo,
{
    pub consumed_kudo: K,         // consumed resource - compliance unit 1
    pub created_kudo: K,          // created resource - compliance unit 1
    pub consumed_denomination: D, // consumed resource - compliance unit 2
    pub created_denomination: D,  // created resource - compliance unit 2
    pub padding_resource_logic: PaddingResourceLogic, // consumed resource - compliance unit 3
    pub created_receive: R,       // created resource - compliance unit 3
}

impl<K, D, R> Transfer<K, D, R>
where
    K: KudoInfo,
    D: DenominationInfo,
    R: ReceiveInfo,
{
    pub fn create_tx(&self) -> Transaction {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units Compliance unit 1: the consumed kudo
            // resource and the consumed denomination resource

            println!("Generating compliance unit 1");
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources_with_path(
                        self.consumed_kudo.resource(),
                        self.consumed_kudo.nf_key().unwrap(),
                        self.consumed_kudo.merkle_path().unwrap(),
                        self.created_kudo.resource(),
                    );

                (
                    ComplianceUnit::create(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 2: the created kudo resource and the created
            // denomination resource
            println!("Generating compliance unit 2");
            let (compliance_unit_2, delta_witness_2) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.consumed_denomination.resource(),
                        self.consumed_denomination.nf_key().unwrap(),
                        self.created_denomination.resource(),
                    );

                (
                    ComplianceUnit::create(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 3: the receive loigc resource and the padding
            // resource
            println!("Generating compliance unit 3");
            let (compliance_unit_3, delta_witness_3) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources(
                        self.padding_resource_logic.witness().resource.clone(),
                        self.padding_resource_logic.witness().nf_key.clone(),
                        self.created_receive.resource(),
                    );

                (
                    ComplianceUnit::create(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the consumed kudo logic proof");
            let consumed_kudo_proof = self.consumed_kudo.prove();

            println!(
                "Generating the denomination logic proof corresponding to the consumed kudo resource"
            );
            let consumed_denomination_proof = self.consumed_denomination.prove();

            println!("Generating the created kudo logic proof");
            let created_kudo_proof = self.created_kudo.prove();

            println!("Generating the denomination logic proof corresponding to the created kudo resource");
            let created_denomination_proof = self.created_denomination.prove();

            println!("Generating the padding resource logic proof");
            let padding_resource_proof = self.padding_resource_logic.prove();

            println!("Generating the receive logic proof");
            let receive_logic_proof = self.created_receive.prove();

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
                    vec![],
                ),
                DeltaWitness::from_bytes_vec(&[delta_witness_1, delta_witness_2, delta_witness_3]),
            )
        };

        // Create the transaction
        Transaction::create(vec![action], Delta::Witness(delta_witness))
    }
}

use crate::resource_info::{DenominationInfo, KudoInfo};
use aarm::{
    action::Action,
    compliance_unit::ComplianceUnit,
    transaction::{Delta, Transaction},
};
use aarm_core::{
    compliance::ComplianceWitness, constants::COMMITMENT_TREE_DEPTH, delta_proof::DeltaWitness,
};

#[derive(Clone)]
pub struct Burn<K, D>
where
    K: KudoInfo,
    D: DenominationInfo,
{
    pub burned_kudo: K,            // consumed resource
    pub burned_denomination: D,    // created resource
    pub ephemeral_kudo: K,         // created resource
    pub ephemeral_denomination: D, // consumed resource
}

impl<K, D> Burn<K, D>
where
    K: KudoInfo,
    D: DenominationInfo,
{
    pub fn create_tx(&self) -> Transaction {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units
            // Compliance unit 1: the ephemeral_kudo_resource and the issued_kudo_resource

            println!("Generating compliance unit 1");
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness: ComplianceWitness<COMMITMENT_TREE_DEPTH> =
                    ComplianceWitness::from_resources_with_path(
                        self.burned_kudo.resource(),
                        self.burned_kudo.nf_key().unwrap(),
                        self.burned_kudo.merkle_path().unwrap(),
                        self.burned_denomination.resource(),
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
                        self.ephemeral_denomination.resource(),
                        self.ephemeral_denomination.nf_key().unwrap(),
                        self.ephemeral_kudo.resource(),
                    );

                (
                    ComplianceUnit::prove(&compliance_witness),
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the burned kudo logic proof");
            let burned_kudo_proof = self.burned_kudo.prove();

            println!(
                "Generating the denomination logic proof corresponding to the burned kudo resource"
            );
            let burned_denomination_proof = self.burned_denomination.prove();

            println!("Generating the ephemeral kudo logic proof");
            let ephemeral_kudo_proof = self.ephemeral_kudo.prove();

            println!("Generating the denomination logic proof corresponding to the ephemeral kudo resource");
            let ephemeral_denomination_proof = self.ephemeral_denomination.prove();

            (
                Action::new(
                    vec![compliance_unit_1, compliance_unit_2],
                    vec![
                        burned_kudo_proof,
                        burned_denomination_proof,
                        ephemeral_kudo_proof,
                        ephemeral_denomination_proof,
                    ],
                    vec![],
                ),
                DeltaWitness::from_bytes_vec(&[delta_witness_1, delta_witness_2]),
            )
        };

        // Create the transaction
        Transaction::new(vec![action], Delta::Witness(delta_witness))
    }
}

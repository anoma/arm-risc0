use crate::resource_info::{DenominationInfo, KudoInfo};
use arm::{
    action::Action,
    compliance_unit::ComplianceUnit,
    error::ArmError,
    transaction::{Delta, Transaction},
    Digest,
};
use arm::{compliance::ComplianceWitness, delta_proof::DeltaWitness};

#[derive(Clone)]
pub struct Burn<K, D>
where
    K: KudoInfo,
    D: DenominationInfo,
{
    pub burned_kudo: K,            // consumed resource - compliance unit 1
    pub ephemeral_kudo: K,         // created resource - compliance unit 1
    pub ephemeral_denomination: D, // consumed resource - compliance unit 2
    pub burned_denomination: D,    // created resource - compliance unit 2
}

impl<K, D> Burn<K, D>
where
    K: KudoInfo,
    D: DenominationInfo,
{
    pub fn create_tx(&self, latest_root: Digest) -> Result<Transaction, ArmError> {
        // Create the action
        let (action, delta_witness) = {
            // Generate compliance units
            // Compliance unit 1: the ephemeral_kudo_resource and the issued_kudo_resource

            println!("Generating compliance unit 1");
            let (compliance_unit_1, delta_witness_1) = {
                let compliance_witness: ComplianceWitness =
                    ComplianceWitness::from_resources_with_path(
                        self.burned_kudo.resource(),
                        self.burned_kudo
                            .nf_key()
                            .ok_or(ArmError::MissingField("Burned kudo nullifier key"))?,
                        self.burned_kudo
                            .merkle_path()
                            .ok_or(ArmError::MissingField("Burned kudo merkle path"))?,
                        self.ephemeral_kudo.resource(),
                    );

                (
                    ComplianceUnit::create(&compliance_witness)?,
                    compliance_witness.rcv,
                )
            };

            // Compliance unit 2: the issued_receive_resource and the issued_denomination_resource
            println!("Generating compliance unit 2");
            let (compliance_unit_2, delta_witness_2) = {
                let compliance_witness: ComplianceWitness = ComplianceWitness::from_resources(
                    self.ephemeral_denomination.resource(),
                    latest_root,
                    self.ephemeral_denomination
                        .nf_key()
                        .ok_or(ArmError::MissingField(
                            "Ephemeral denomination nullifier key",
                        ))?,
                    self.burned_denomination.resource(),
                );

                (
                    ComplianceUnit::create(&compliance_witness)?,
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the burned kudo logic proof");
            let burned_kudo_proof = self.burned_kudo.prove()?;

            println!(
                "Generating the denomination logic proof corresponding to the burned kudo resource"
            );
            let burned_denomination_proof = self.burned_denomination.prove()?;

            println!("Generating the ephemeral kudo logic proof");
            let ephemeral_kudo_proof = self.ephemeral_kudo.prove()?;

            println!("Generating the denomination logic proof corresponding to the ephemeral kudo resource");
            let ephemeral_denomination_proof = self.ephemeral_denomination.prove()?;

            (
                Action::new(
                    vec![compliance_unit_1, compliance_unit_2],
                    vec![
                        burned_kudo_proof,
                        ephemeral_kudo_proof,
                        ephemeral_denomination_proof,
                        burned_denomination_proof,
                    ],
                )?,
                DeltaWitness::from_bytes_vec(&[delta_witness_1, delta_witness_2])?,
            )
        };

        // Create the transaction
        Ok(Transaction::create(
            vec![action],
            Delta::Witness(delta_witness),
        ))
    }
}

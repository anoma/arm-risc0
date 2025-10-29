use crate::resource_info::{DenominationInfo, KudoInfo, ReceiveInfo};
use arm::{
    action::Action,
    compliance::ComplianceWitness,
    compliance_unit::ComplianceUnit,
    delta_proof::DeltaWitness,
    error::ArmError,
    resource::ConsumedDatum,
    transaction::{Delta, Transaction},
    Digest,
};

#[derive(Clone)]
pub struct Transfer<K, D, R>
where
    K: KudoInfo,
    D: DenominationInfo,
    R: ReceiveInfo,
{
    pub consumed_kudo: K,         // consumed resource
    pub created_kudo: K,          // created resource
    pub consumed_denomination: D, // consumed resource
    pub created_denomination: D,  // created resource
    pub created_receive: R,       // created resource
}

impl<K, D, R> Transfer<K, D, R>
where
    K: KudoInfo,
    D: DenominationInfo,
    R: ReceiveInfo,
{
    pub fn create_tx(&self, latest_root: Digest) -> Result<Transaction, ArmError> {
        // Create the action
        let (action, delta_witness) = {
            println!("Generating compliance unit");
            let (compliance_unit, delta_witness) = {
                let mut consumed_data = Vec::new();
                let mut created_resources = Vec::new();

                // 1. the consumed kudo resource and the consumed denomination resource
                let consumed_datum = ConsumedDatum::from_resource_with_path(
                    self.consumed_kudo.resource(),
                    self.consumed_kudo
                        .nf_key()
                        .ok_or(ArmError::MissingField("Consumed kudo nullifier key"))?,
                    self.consumed_kudo
                        .merkle_path()
                        .ok_or(ArmError::MissingField("Consumed kudo merkle path"))?,
                );
                consumed_data.push(consumed_datum);
                created_resources.push(self.created_kudo.resource());

                // 2. the created kudo resource and the created denomination resource
                let consumed_datum = ConsumedDatum::from_resource(
                    self.consumed_denomination.resource(),
                    self.consumed_denomination
                        .nf_key()
                        .ok_or(ArmError::MissingField(
                            "Consumed denomination nullifier key",
                        ))?,
                );
                consumed_data.push(consumed_datum);
                created_resources.push(self.created_denomination.resource());

                // 3. the receive logic resource
                created_resources.push(self.created_receive.resource());

                let compliance_witness = ComplianceWitness::from_resources_info_with_eph_root(
                    &consumed_data,
                    &created_resources,
                    latest_root,
                );

                (
                    ComplianceUnit::create(&compliance_witness)?,
                    compliance_witness.rcv,
                )
            };

            // Generate logic proofs
            println!("Generating the consumed kudo logic proof");
            let consumed_kudo_proof = self.consumed_kudo.prove()?;

            println!(
                "Generating the denomination logic proof corresponding to the consumed kudo resource"
            );
            let consumed_denomination_proof = self.consumed_denomination.prove()?;

            println!("Generating the created kudo logic proof");
            let created_kudo_proof = self.created_kudo.prove()?;

            println!("Generating the denomination logic proof corresponding to the created kudo resource");
            let created_denomination_proof = self.created_denomination.prove()?;

            println!("Generating the receive logic proof");
            let receive_logic_proof = self.created_receive.prove()?;

            (
                Action::new(
                    compliance_unit,
                    vec![
                        consumed_kudo_proof,
                        consumed_denomination_proof,
                        created_kudo_proof,
                        created_denomination_proof,
                        receive_logic_proof,
                    ],
                )?,
                DeltaWitness::from_bytes(&delta_witness)?,
            )
        };

        // Create the transaction
        Ok(Transaction::create(
            vec![action],
            Delta::Witness(delta_witness),
        ))
    }
}

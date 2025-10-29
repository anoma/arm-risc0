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
pub struct Issue<K, D, R>
where
    K: KudoInfo,
    D: DenominationInfo,
    R: ReceiveInfo,
{
    pub ephemeral_kudo: K,         // consumed resource
    pub issue_kudo: K,             // created resource
    pub issue_receive: R,          // created resource
    pub issue_denomination: D,     // created resource
    pub ephemeral_denomination: D, // created resource
}

impl<K, D, R> Issue<K, D, R>
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

                // 1. the ephemeral_kudo_resource and the issued_kudo_resource
                let consumed_datum = ConsumedDatum::from_resource(
                    self.ephemeral_kudo.resource(),
                    self.ephemeral_kudo
                        .nf_key()
                        .ok_or(ArmError::MissingField("Ephemeral kudo nullifier key"))?,
                );
                consumed_data.push(consumed_datum);
                created_resources.push(self.issue_kudo.resource());

                // 2. the issued_receive_resource and the issued_denomination_resource
                created_resources.push(self.issue_receive.resource());
                created_resources.push(self.issue_denomination.resource());

                // 3. the ephemeral_denomination_resource
                created_resources.push(self.ephemeral_denomination.resource());

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
            println!("Generating the issued kudo logic proof");
            let issued_kudo_proof = self.issue_kudo.prove()?;

            println!("Generating the issued denomination logic proof");
            let issue_denomination_proof = self.issue_denomination.prove()?;

            println!("Generating the issued receive logic proof");
            let issued_receive_logic_proof = self.issue_receive.prove()?;

            println!("Generating the ephemeral kudo logic proof");
            let ephemeral_kudo_proof = self.ephemeral_kudo.prove()?;

            println!("Generating the ephemeral denomination logic proof");
            let ephemeral_denomination_proof = self.ephemeral_denomination.prove()?;

            (
                Action::new(
                    compliance_unit,
                    vec![
                        issued_kudo_proof,
                        issue_denomination_proof,
                        issued_receive_logic_proof,
                        ephemeral_kudo_proof,
                        ephemeral_denomination_proof,
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

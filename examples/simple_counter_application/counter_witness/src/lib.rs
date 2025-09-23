pub use arm::resource_logic::LogicCircuit;
use arm::{
    encryption::{AffinePoint, Ciphertext, SecretKey},
    error::ArmError,
    logic_instance::{AppData, ExpirableBlob, LogicInstance},
    merkle_path::MerklePath,
    nullifier_key::NullifierKey,
    resource::Resource,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CounterWitness {
    pub is_consumed: bool,
    pub old_counter: Resource,
    pub old_counter_existence_path: MerklePath,
    pub nf_key: NullifierKey,
    pub new_counter: Resource,
    pub new_counter_existence_path: MerklePath,
    pub discovery_pk: AffinePoint, // From the receiver
    pub discovery_sk: SecretKey,   // randomly generated
    pub discovery_nonce: [u8; 12], // randomly generated
}

impl CounterWitness {
    pub fn new(
        is_consumed: bool,
        old_counter: Resource,
        old_counter_existence_path: MerklePath,
        nf_key: NullifierKey,
        new_counter: Resource,
        new_counter_existence_path: MerklePath,
        discovery_pk: AffinePoint,
    ) -> Self {
        Self {
            is_consumed,
            old_counter,
            old_counter_existence_path,
            nf_key,
            new_counter,
            new_counter_existence_path,
            discovery_pk,
            discovery_sk: SecretKey::random(),
            discovery_nonce: rand::random(),
        }
    }
}

impl LogicCircuit for CounterWitness {
    fn constrain(&self) -> Result<LogicInstance, ArmError> {
        // Load resources
        let old_nf = self.old_counter.nullifier(&self.nf_key)?;
        let new_cm = self.new_counter.commitment();

        // Check existence paths
        let old_counter_root = self.old_counter_existence_path.root(&old_nf);
        let new_counter_root = self.new_counter_existence_path.root(&new_cm);
        assert_eq!(old_counter_root, new_counter_root);

        assert_eq!(self.old_counter.quantity, 1);
        assert_eq!(self.new_counter.quantity, 1);

        let old_counter_value: u128 = u128::from_le_bytes(
            self.old_counter.value_ref[0..16]
                .try_into()
                .map_err(|_| ArmError::InvalidResourceValueRef)?,
        );
        let new_counter_value: u128 = u128::from_le_bytes(
            self.new_counter.value_ref[0..16]
                .try_into()
                .map_err(|_| ArmError::InvalidResourceValueRef)?,
        );

        // Init a new counter resource with the value 1
        if self.old_counter.is_ephemeral {
            assert_eq!(new_counter_value, 1);
        }

        // Check that the new counter value is one more than the old counter value
        assert_eq!(new_counter_value, old_counter_value + 1);

        let tag = if self.is_consumed { old_nf } else { new_cm };

        let discovery_payload = {
            let cipher = Ciphertext::encrypt(
                &vec![0u8],
                &self.discovery_pk,
                &self.discovery_sk,
                self.discovery_nonce,
            );
            let cipher_expirable_blob = ExpirableBlob {
                blob: cipher.as_words(),
                deletion_criterion: 1,
            };
            vec![cipher_expirable_blob]
        };

        let app_data = AppData {
            discovery_payload,
            ..Default::default()
        };

        Ok(LogicInstance {
            tag: tag.as_words().to_vec(),
            is_consumed: self.is_consumed,
            root: old_counter_root,
            app_data,
        })
    }
}

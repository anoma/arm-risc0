pub mod minimal;
mod shared_constraints;
pub mod sigmabus;
pub mod var;
use crate::error::ArmError;
use crate::utils::words_to_bytes;

use k256::{elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, ProjectivePoint};
pub use minimal::ComplianceInstance;
pub use minimal::ComplianceWitness;
use serde::Serialize;
pub use sigmabus::ComplianceSigmabusWitness;
pub use sigmabus::SigmaBusCircuitInstance;
pub use sigmabus::SigmabusCircuitWitness;
pub use sigmabus::TX_MAX_RESOURCES;
pub use var::ComplianceVarInstance;
pub use var::ComplianceVarWitness;

use hex::FromHex;
use lazy_static::lazy_static;
use risc0_zkvm::Digest;
lazy_static! {
    pub static ref INITIAL_ROOT: Digest =
        Digest::from_hex("cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06")
            .unwrap();
}

/// Public information of consumed resources.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ConsumedMemorandum {
    /// The nullifier of the consumed [Resource]
    pub resource_nullifier: Digest,
    /// The logic reference of the consumed [Resource]
    pub resource_logic_ref: Digest,
    /// The root of the Merkle tree where the resource commitment is in.
    pub commitment_tree_root: Digest,
}

/// Public information of created resources.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct CreatedMemorandum {
    /// The commitment to the created [Resource]
    pub resource_commitment: Digest,
    /// The logic reference of the created [Resource].
    pub resource_logic_ref: Digest,
}

/// This is a trait for compliance constraints implementation.
pub trait ComplianceCircuit: Serialize {
    type Instance;

    /// The code run in the zkVM
    fn constrain(&self) -> Result<Self::Instance, ArmError>;
}

/// A trait to abstract common functionality of compliance instances.
pub trait CI {
    /// Returns the public information of the consumed resources
    /// of this compliance instance
    fn consumed_info(&self) -> Vec<ConsumedMemorandum>;

    /// Returns the public information of the created resources
    /// of this compliance instance
    fn created_info(&self) -> Vec<CreatedMemorandum>;

    /// The delta commitment of this compliance instance.
    fn delta(&self) -> Result<ProjectivePoint, ArmError>;

    /// Returns the contribution of this compliance instance to the delta message.
    /// Namely, the list of tags as bytes.
    fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        for tag in self
            .consumed_info()
            .iter()
            .map(|memo| memo.resource_nullifier)
            .chain(
                self.created_info()
                    .iter()
                    .map(|memo| memo.resource_commitment),
            )
        {
            msg.extend_from_slice(tag.as_bytes());
        }
        msg
    }
}

fn to_delta_projective(delta_x: [u32; 8], delta_y: [u32; 8]) -> Result<ProjectivePoint, ArmError> {
    let encoded_point = EncodedPoint::from_affine_coordinates(
        words_to_bytes(&delta_x).into(),
        words_to_bytes(&delta_y).into(),
        false,
    );
    ProjectivePoint::from_encoded_point(&encoded_point)
        .into_option()
        .ok_or(ArmError::InvalidDelta)
}

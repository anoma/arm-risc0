pub mod minimal;
mod shared_constraints;
pub mod sigmabus;
pub mod var;
use crate::error::ArmError;

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

/// This is a trait for compliance constraints implementation.
pub trait ComplianceCircuit: Serialize {
    type Instance;

    /// The code run in the zkVM
    fn constrain(&self) -> Result<Self::Instance, ArmError>;
}

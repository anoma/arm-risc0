use crate::compliance_info::ComplianceWitnessInfo;
use arm::logic_proof::LogicProver;

// TODO: Add methods for specific types
pub trait KudoInfo: ComplianceWitnessInfo + LogicProver {
    // Additional methods specific to KudoInfo can be defined here
}
pub trait DenominationInfo: ComplianceWitnessInfo + LogicProver {
    // Additional methods specific to DenominationInfo can be defined here
}
pub trait ReceiveInfo: ComplianceWitnessInfo + LogicProver {
    // Additional methods specific to ReceiveInfo can be defined here
}

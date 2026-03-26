#[derive(Debug)]
pub enum ArmError {
    InvalidNullifierKey,
    InvalidResourceKind,
    InvalidRcv,
    InvalidDelta,
}

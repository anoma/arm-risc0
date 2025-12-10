#[cfg(target_arch = "bpf")]
mod solana;

#[cfg(not(target_arch = "bpf"))]
mod other;

use crate::error::ArmError;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct EthRecoveryId(u8);

impl EthRecoveryId {
    pub fn is_odd(self) -> bool {
        // 27 odd, 28 even
        self.0 == 27
    }
}

impl TryFrom<u8> for EthRecoveryId {
    type Error = ArmError;

    fn try_from(recid: u8) -> Result<Self, Self::Error> {
        if recid == 27 || recid == 28 {
            Ok(Self(recid))
        } else {
            Err(ArmError::InvalidSignature)
        }
    }
}

impl From<EthRecoveryId> for u8 {
    fn from(recid: EthRecoveryId) -> u8 {
        recid.0
    }
}

//#[cfg(not(target_os = "solana"))]
#[cfg(not(target_arch = "bpf"))]
impl TryFrom<k256::ecdsa::RecoveryId> for EthRecoveryId {
    type Error = ArmError;

    fn try_from(recid: k256::ecdsa::RecoveryId) -> Result<Self, Self::Error> {
        let recid = recid.to_byte();

        if recid <= 1 {
            Ok(Self(recid + 27))
        } else {
            Err(ArmError::InvalidSignature)
        }
    }
}

//#[cfg(not(target_os = "solana"))]
#[cfg(not(target_arch = "bpf"))]
impl From<EthRecoveryId> for k256::ecdsa::RecoveryId {
    fn from(recid: EthRecoveryId) -> Self {
        Self::from_byte(recid.0 - 27).expect("value of EthRecoveryId should be 27 or 28")
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct VerifyingKey([u8; 32]);

impl VerifyingKey {
    pub fn recover(
        &self,
        prehashed: &[u8; 32],
        recid: EthRecoveryId,
        signature: &Signature,
    ) -> VerifyingKey {
        todo!()
    }
}

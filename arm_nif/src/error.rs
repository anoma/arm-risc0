//! Error type bridging arm-risc0 / bincode failures to Erlang terms.

use anoma_rm_risc0::error::ArmError;
use rustler::{Encoder, Env, Term};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArmNifError {
    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] bincode::Error),
    #[error("ARM error: {0}")]
    Arm(#[from] ArmError),
}

impl Encoder for ArmNifError {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.to_string().encode(env)
    }
}

impl From<ArmNifError> for rustler::Error {
    fn from(e: ArmNifError) -> Self {
        rustler::Error::Term(Box::new(e))
    }
}

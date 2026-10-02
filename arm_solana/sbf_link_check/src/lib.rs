//! A Solana program whose only job is to be linked for SBF. A library build
//! (`cargo build-sbf` on `anoma-rm-solana` itself) produces an rlib and never
//! resolves syscall symbols; linking this cdylib does, for every syscall the
//! verifiers reach.

use anoma_rm_core::transaction::Transaction;
use anoma_rm_solana::delta::verify_delta_proof;
use anoma_rm_solana::journal::{aggregation_journal_digest, require_aggregation};
use borsh::BorshDeserialize;
use solana_account_info::AccountInfo;
use solana_program_entrypoint::{entrypoint, ProgramResult};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

entrypoint!(process_instruction);

fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let tx = Transaction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let instance = require_aggregation(&tx).map_err(|e| ProgramError::Custom(e as u32))?;
    verify_delta_proof(&tx).map_err(|e| ProgramError::Custom(e as u32))?;
    aggregation_journal_digest(instance);
    Ok(())
}

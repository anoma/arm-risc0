# Anoma Resource Machine on Solana

Transaction verification for the Anoma Shielded Resource Machine inside Solana programs.

## Overview

The `anoma-rm-solana` crate verifies transactions of the Anoma Shielded Resource Machine on-chain. It builds on the types of [`anoma-rm-core`](../arm_core/README.md) and performs the same checks as `anoma-rm-risc0` with the primitives of the Solana runtime, because RISC0 zkVM and k256 cannot run inside a Solana program:

- **Delta Proof Verification**: Checks the balance proof of an aggregated transaction with the keccak256 and secp256k1 recovery syscalls and `solana-secp256k1` point addition
- **Aggregation Journal Digest**: Computes the sha256 digest of the batch aggregation journal with the sha256 syscall, which is the public input for verifying the aggregation proof on-chain

Only aggregated transactions are accepted. The aggregation proof itself is a Groth16 proof and is verified by the caller (for example through the RISC0 verifier router program); this crate supplies the journal digest that verification needs.

Delta proof verification accepts and rejects exactly the transactions `anoma-rm-risc0` accepts and rejects; the tests check every step of it against k256.

## Key Components

### Core Modules

- **`journal`**: `require_aggregation` returns the aggregation instance of an aggregated transaction; `aggregation_journal_digest` computes the sha256 digest of its journal
- **`delta`**: `verify_delta_proof` and its steps: delta message hash, delta point accumulation and signature recovery
- **`error`**: `SolanaArmError`, the errors of on-chain verification

## Usage

Add to your `Cargo.toml`:

```toml
anoma-rm-solana = "2.0.0-rc.5"
```

Inside a Solana program:

```rust
use anoma_rm_core::transaction::Transaction;
use anoma_rm_solana::delta::verify_delta_proof;
use anoma_rm_solana::journal::{aggregation_journal_digest, require_aggregation};

let tx: Transaction = /* deserialized from the instruction data */;
let instance = require_aggregation(&tx)?;
verify_delta_proof(&tx)?;
// Verify the aggregation proof against BATCH_AGGREGATION_VK with this digest as the journal digest.
let journal_digest = aggregation_journal_digest(instance);
```

## Documentation

For more information, refer to:

- [Anoma Resource Machine Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

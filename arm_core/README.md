# Anoma Resource Machine Core

The data types of the Anoma Shielded Resource Machine, shared by every implementation.

## Overview

The `anoma-rm-core` crate provides the types and the checks that need no proof generation:

- **Resource Management**: Defines resources, their commitments and nullifiers
- **Transaction Structure**: Transactions, actions, compliance units and logic proofs, with their serialization
- **Structural Checks**: Action trees, Merkle paths, kind table commitments and the encoding of delta proofs

It does not depend on RISC0 zkVM, k256 or a random number generator, so it compiles for targets where those cannot run, such as Solana programs. Proof generation and verification live in `anoma-rm-risc0` (host and zkVM) and `anoma-rm-solana` (Solana programs), which both build on this crate. `anoma-rm-risc0` re-exports every module below, so its users do not need to depend on `anoma-rm-core` directly.

## Key Components

### Core Modules

- **`resource`**: Resource definition and serialization, commitment and nullifier derivation
- **`resource_logic`**: Logic circuit trait and the trivial logic
- **`transaction`**: Transaction structure and representation checks
- **`action`**: Actions within transactions
- **`action_tree`**: Merkle tree over the tags of an action
- **`compliance`**: Compliance instance and witness, kind table commitment
- **`compliance_unit`**: Compliance proof paired with its instance
- **`logic_proof`**: Zero-knowledge proof structures for resource logic
- **`logic_instance`**: Public inputs of resource logic proofs
- **`delta_proof`**: Balance proof for state changes, as signature and witness bytes
- **`aggregation_instance`**: Public inputs of the batch aggregation proof and their journal encoding
- **`aggregation_witness`**: Witness passed to the batch aggregation circuit
- **`merkle_path`**: Merkle path in the commitment tree
- **`nullifier_key`**: Nullifier key and its commitment
- **`constants`**: Verifying keys (image IDs) of the compliance, trivial logic and batch aggregation circuits

## Features

- `borsh`: Enables Borsh serialization of all types (used by Solana programs)

## Usage

Add to your `Cargo.toml`:

```toml
# Default configuration
anoma-rm-core = "2.0.0-rc.5"

# With Borsh serialization
anoma-rm-core = { version = "2.0.0-rc.5", features = ["borsh"] }
```

## Documentation

For more information, refer to:

- [Anoma Resource Machine Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

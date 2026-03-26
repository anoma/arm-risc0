# Anoma Resource Machine Core Types

Pure data types and serialization for the Anoma Shielded Resource Machine, with no dependencies on risc0-zkvm or k256.

## Overview

The `anoma-rm-core` crate provides the foundational types shared across the ARM crate family. It defines resources, transactions, compliance instances, Merkle paths, and related structures without pulling in cryptographic or zkVM dependencies.

## Key Components

- **`action`**: A set of compliance units and logic verifier inputs
- **`compliance`**: `ComplianceInstance` and `ComplianceInstanceWords` — public instance data committed to by compliance proofs
- **`compliance_unit`**: `ComplianceUnit` — pairs a proof with its compliance instance
- **`constants`**: Verification key bytes (image IDs) for compliance, padding logic, and batch aggregation circuits
- **`delta_types`**: `DeltaProof` and `DeltaWitness` — types for delta (value balance) proofs
- **`digest`**: `Digest` — a 32-byte hash wrapper with serialization support
- **`error`**: `ArmError` — shared error type
- **`logic_instance`**: `LogicInstance`, `LogicVerifierInputs`, `AppData`, `ExpirableBlob` — resource logic verification data
- **`merkle_path`**: `MerklePath` and `padding_leaf` — Merkle tree inclusion proof types
- **`nullifier_key`**: `NullifierKey` and `NullifierKeyCommitment`
- **`transaction`**: `Transaction` and `Delta` — the top-level transaction type
- **`utils`**: Conversion helpers (`bytes_to_words`, `words_to_bytes`)

## Usage

Add to your `Cargo.toml`:

```toml
arm-core = { package = "anoma-rm-core", path = "../arm_core" }
```

## Documentation

For more information, refer to:

- [Anoma Resource Machine Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

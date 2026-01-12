# Anoma Resource Machine based on RISC0

A Rust implementation of the Anoma Shielded Resource Machine using [RISC0 zkVM](https://github.com/risc0/risc0) for zero-knowledge proofs.

## Overview

The `anoma-rm-risc0` crate provides the core functionality of a resource-based state machine designed for the Anoma protocol. It implements:

- **Resource Management**: Defines and manages cryptographic resources with associated logic
- **Transaction Processing**: Builds and validates transactions with compliance and logic checks
- **Proof Generation**: Creates zero-knowledge proofs for transaction validity using RISC0
- **Aggregation**: Enables proof aggregation and composition (single-run and IVC-based)

## Key Components

### Core Modules

- **`resource`**: Resource definition and serialization
- **`resource_logic`**: Custom logic and constraints for resources
- **`transaction`**: Transaction structure and validation
- **`action`**: Actions within transactions and their hierarchical organization
- **`compliance`**: Compliance verification logic
- **`logic_proof`**: Zero-knowledge proof structures for resource logic
- **`delta_proof`**: Balance proof for state changes

### Optional Modules

- **`aggregation`**: Proof aggregation (batch and sequential IVC)

## Features

The crate supports several features to control compilation and functionality:

- `transaction` (default): Enables transaction processing and compliance checking
- `prove` (default): Enables proof generation with RISC0
- `bonsai`: Enables remote proof execution via Bonsai
- `cuda`: Enables CUDA acceleration for proofs
- `aggregation`: Enables proof aggregation support

## Usage

Add to your `Cargo.toml`:

```toml
# Default configuration
anoma-rm-risc0 ="1.0.0"

# Proof aggregation (a single succinct proof per transaction)
anoma-rm-risc0 ={ version = "1.0.0", features = ["aggregation"] }

# Logic-circuit-only usage
anoma-rm-risc0 ={ version = "1.0.0", default-features = false }
```

## Documentation

For more information, refer to:

- [Anoma Resource Machine Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

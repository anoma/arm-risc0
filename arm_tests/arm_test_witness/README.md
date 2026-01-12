# Anoma Resource Machine Test Witness

Witness definitions and logic circuit implementation for testing the Anoma Resource Machine (ARM) using RISC0 zkVM.

## Overview

The `anoma-rm-risc0-test-witness` crate provides a minimal, practical witness and logic circuit used by the test app to validate ARM transaction flows. It demonstrates:

- Constructing a `LogicCircuit` with resource, discovery, and application payloads
- Integrating EVM-compatible resource encoding
- Using authenticated encryption for payloads
- Building a `LogicInstance` tag with Merkle proofs and nullifier keys

## Usage

Add as a dev dependency in a test app or examples:

```toml
[dependencies]
anoma-rm-risc0-test-witness = "1.0"
```

## Relationship to Test App

This crate is consumed by the `anoma-rm-risc0-test-app` crate, which:
- Implements a `LogicProver` that uses `TestLogicWitness`
- Generates actions, transactions, and delta proofs for end-to-end tests
- Verifies proofs and exercises aggregation strategies

## License

Apache-2.0. See [LICENSE](../../LICENSE).

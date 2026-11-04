# arm-risc0

This folder specifies arm-risc0, the RISC Zero implementation of the Anoma Resource Machine (ARM). The protocol adapters verify its proofs on chain. The glossary of this repository, [`CONTEXT.md`](../CONTEXT.md#language), defines the terms.

## 1. Summary

arm-risc0 proves the transactions of the ARM with RISC Zero. Each action has one compliance unit, whose compliance proof shows the compliance checks of its ordered list of resources: their commitments, nullifiers, nonces and kind bases. One aggregation proof covers the compliance proofs and the resource logic proofs of a transaction, and the delta proof shows that the transaction balances.

## 2. Documents

| Document                                                           | Content                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`01-compliance-units.md`](./01-compliance-units.md)               | Each action has one compliance unit. It holds one or more consumed resources and any number of created resources, in one ordered list. Logic proof `i` belongs to resource `i` of the list.                                                                           |
| [`02-nonce-derivation.md`](./02-nonce-derivation.md)               | The nonce of each created resource derives from its index among the created resources and from all consumed nullifiers of its unit.                                                                                                                                   |
| [`03-kind-tree.md`](./03-kind-tree.md)                             | The compliance circuit reads the kind base of a resource from a kind tree if the prover gives a kind path, else it calculates the kind base by hash to curve. Aliases in the tree make kinds fungible.                                                                |
| [`04-proofs-and-verification.md`](./04-proofs-and-verification.md) | The delta proof signs the action tree roots. One aggregation proof covers all compliance units and logic proofs of a transaction, and its journal has an encoding for EVM verifiers. The out-of-circuit checks of a verifier cover what the in-circuit checks do not. |
| [`05-legacy-version.md`](./05-legacy-version.md)                   | How arm-risc0 differs from its legacy version, whose proofs the legacy protocol adapters verify                                                                                                                                                                       |

## 3. Crates

- `anoma-rm-core`, in the folder `arm_core`, holds the data types, their encodings and the SHA-256 calculations: commitments, nullifiers and tree roots. It does not prove or verify, and it uses `risc0-zkp` only for `Digest` and SHA-256. So each verifier can use it.
- `anoma-rm-risc0`, in the folder `arm`, holds the curve arithmetic, proving and verification with RISC Zero. It exports the core types again.
- `anoma-rm-solana`, in the folder `arm_solana`, verifies aggregated transactions on Solana.

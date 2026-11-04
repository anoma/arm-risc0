# Legacy Version

This document states how arm-risc0 differs from its legacy version. The legacy protocol adapters verify proofs of the legacy version: they store the verifying keys of its circuits. The glossary [`CONTEXT.md`](../CONTEXT.md#language) defines the terms.

The comparisons hold for the tag `v1.1.1`.

## 1. Differences

| Part                        | Legacy version                                                                                                                                                                                 | arm-risc0                                                                                                                                                                  | Specified in                                                       |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Compliance unit             | Each unit holds one consumed and one created resource. An action holds many units, and padding resources fill them. A verifier finds the logic proof of a resource by its tag.                 | Each action has one unit. It holds one or more consumed resources and any number of created resources, in one ordered list. Logic proof `i` belongs to resource `i`.       | [`01-compliance-units.md`](./01-compliance-units.md)               |
| Nonce of a created resource | The nullifier of the consumed resource of the same unit. An in-circuit check of the compliance circuit requires this equality.                                                                 | Derived from the index of the created resource and from all consumed nullifiers of the unit                                                                                | [`02-nonce-derivation.md`](./02-nonce-derivation.md)               |
| Kind base                   | Always calculated from the kind by hash to curve. So resources of two different kinds never balance against each other.                                                                        | Read from a kind tree if the prover gives a kind path, else calculated by hash to curve. Aliases in the tree make kinds fungible.                                          | [`03-kind-tree.md`](./03-kind-tree.md)                             |
| Delta message               | The nullifier and the commitment of each compliance unit                                                                                                                                       | The action tree root of each action                                                                                                                                        | [`04-proofs-and-verification.md`](./04-proofs-and-verification.md) |
| Aggregation circuit         | Verifies the proofs and outputs all its inputs. The verifier calculates each action tree root out of circuit, and an out-of-circuit check shows that the logic proofs belong to the resources. | Verifies the proofs, calculates the action tree root of each action, has an in-circuit check that each logic proof belongs to its resource, and outputs a compact instance | [`04-proofs-and-verification.md`](./04-proofs-and-verification.md) |
| Journal encodings           | RISC Zero encoding                                                                                                                                                                             | RISC Zero encoding, and an ABI encoding for EVM verifiers                                                                                                                  | [`04-proofs-and-verification.md`](./04-proofs-and-verification.md) |
| Transaction                 | Actions with optional proofs, and an optional aggregation proof                                                                                                                                | Either actions or an aggregation, never both. The proofs are not optional.                                                                                                 | [`04-proofs-and-verification.md`](./04-proofs-and-verification.md) |
| Crates                      | The data types and the proof system in one crate                                                                                                                                               | The data types in a crate that does not prove or verify                                                                                                                    | [`README.md`](./README.md#2-crates)                                |

These points have no row in the table:

- The delta of the legacy version has the opposite sign. The sign does not change which transactions balance.
- `LogicInstance` has the same encoding in both versions. The legacy version calls its third field `root`.
- Both versions calculate the commitment, the nullifier and the kind of a resource in the same way. So arm-risc0 can consume each resource that the legacy version created.
- `Resource::set_nonce_from_nf` sets the nonce of the legacy version, which `compliance::constrain` rejects.

## 2. Removed parts

- The compliance instance of fixed size, `ComplianceInstanceWords`, and with it the padding resources that fill compliance units
- The function `construct_aggregation_instance`, with which a verifier rebuilt the journal of all inputs
- The feature `aggregation_circuit`

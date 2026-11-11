# Kind Tree

This document specifies the kind tree: how the compliance circuit reads kind bases from it instead of calculating them, and how it makes kinds fungible. The code is in [`arm/src/kind_tree.rs`](../arm/src/kind_tree.rs), [`arm/src/compliance.rs`](../arm/src/compliance.rs) (`resolve_kind`, `constrain`) and [`arm_core/src/compliance.rs`](../arm_core/src/compliance.rs). The glossary [`CONTEXT.md`](../CONTEXT.md#language) defines the terms.

## 1. Two uses

The compliance circuit can read the kind base of a resource from a kind tree instead of calculating it from the kind by hash to curve. This has two uses:

- **No hash to curve with a kind path.** If the prover gives a kind path, the compliance circuit makes an in-circuit check of the Merkle path and does not calculate the kind base. `compliance::from_resources` gives a kind path for each resource whose pair the tree lists.
- **Kind conversion.** If an entry gives a kind the kind base of another kind, the two kinds are aliases. The other kind can have its own entry, or it can have no entry and use its kind base from hash to curve. A transaction can consume resources of one kind and create resources of the other kind for the same quantity.

For a resource without a kind path, the circuit calculates the kind base by hash to curve.

## 2. The tree

A `KindTreeEntry` holds a logic ref, a label ref and a kind base. The kind base is an uncompressed SEC1 point of 65 bytes. `KindTree::from_entries` builds the tree in these steps:

1. It checks that each kind base has 65 bytes, starts with the byte `0x04`, and is on the curve.
2. It sorts the entries by logic ref, then by label ref, and rejects two entries with the same pair (`DuplicateKindTreeEntry`).
3. It calculates each leaf as `SHA-256(logic_ref ‖ label_ref ‖ kind_base)` (`hash_kind_tree_leaf`).
4. It fills the leaves up to a power of two with `PADDING_LEAF`, and it hashes each pair of nodes with SHA-256 up to the root.

The empty tree has the root `PADDING_LEAF`. A tree with one entry has the leaf as its root and an empty path. The tree has no fixed depth, and a kind path can have any length. A leaf hashes 129 bytes and an inner node 64 bytes, without a domain separator, so the soundness of the tree depends on the collision resistance of SHA-256.

A **kind path** is a kind base of an entry and the Merkle path that proves the entry is in the tree. `KindTree::kind_paths_for` gives one optional kind path for each resource of a list: a path if the tree lists the pair of the resource, else none.

## 3. In the compliance circuit

The compliance witness holds one optional kind path for each resource (`kind_paths`). `compliance::constrain` requires one entry for each resource (`KindPathCountMismatch`). It resolves the kind base once for each distinct key: the logic ref, the label ref and the kind path of a resource. A later resource with the same key has the same inputs, so it uses the same kind base. For a resource of the same kind with another kind path, the key is new, so `resolve_kind` checks that path too. For each new key, `resolve_kind` does these steps:

- **With a kind path**, it requires a kind base of 65 bytes that starts with `0x04` (`InvalidKindBaseEncoding`). This also excludes the identity point. It calculates the leaf from the logic ref and the label ref of the resource itself and from the kind base of the path, and then the root from the Merkle path. The first path sets the root of the unit. Each later path must give the same root (`KindPathRootMismatch`). The kind base must be on the curve (`KindBaseNotOnCurve`).
- **Without a kind path**, it calculates the kind base by hash to curve.

The leaf contains the pair of the resource. So a prover can use an entry only for a resource with the pair that the entry names.

`constrain` adds the signed quantity of each resource to the sum of its key. Resources of two aliases have different keys, so they add to two sums. In the delta, each sum is multiplied by its kind base. Aliases have the same kind base, so their consumed and created quantities cancel.

The compliance instance holds the kind tree root of the unit: the root of the kind paths, or `PADDING_LEAF` if the unit uses no kind path.

### Kind conversion

A conversion entry gives a resource the kind base of another kind for balancing. The key of the entry remains the resource's own `(logic_ref, label_ref)` pair. The supplied kind base does not need to equal the hash to curve of that pair: the Merkle path authenticates the mapping, and the verifier's accepted root authorizes it.

The resources participating in a conversion must resolve to the same kind base. Each resource whose base comes from the tree needs a kind path for its own pair. The other kind can use a tree entry with the same base, or omit its path if its hash to curve already gives that base. Omitting a path always selects the resource's own hash-to-curve kind, regardless of entries in the tree.

Resources of aliases contribute to the same balance even though they have different logic refs or label refs. Consumption adds quantity times the resolved base; creation subtracts it. Their contributions can therefore cancel across kinds when the total consumed and created quantities agree. Several resources can participate in this balance, without pairing each consumed resource with a particular created resource. The conversion is 1:1 in quantity and uses the existing delta calculation, without a separate conversion witness, conversion proof or additional balancing term.

## 4. How a verifier accepts the root

- An in-circuit check of the aggregation circuit requires that all actions of a transaction with a root other than `PADDING_LEAF` have the same root. Its journal holds that root, or `PADDING_LEAF` if no action uses a kind path.
- The out-of-circuit check `transaction::kind_tree_root_check` accepts the root of a transaction if it is the expected root or `PADDING_LEAF`.
- The protocol adapter on EVM stores one kind tree root. Its out-of-circuit check accepts a transaction with that root or with the root of the empty tree.

A transaction without kind paths therefore passes these checks with each kind tree. So a kind tree cannot block a kind: a prover can leave out the kind path of a resource, and the circuit then uses the kind base from hash to curve. A kind tree adds aliases, but it cannot stop a kind from balancing with itself.

## 5. Trust assumptions

- **A verifier accepts only the roots of reviewed trees.** The tree decides which kinds are fungible, and no in-circuit or out-of-circuit check of arm-risc0 compares a kind base with its pair. An entry that gives a kind the kind base of another kind lets transactions create resources of one kind from resources of the other. The repository risc0-kind-trees holds the kind trees of the protocol adapters and gives the rules for their entries.
- **Nobody knows a linear relation between the generator `G` of the curve and the different kind bases of a tree.** Equal points, the aliases, are the only permitted relation. A known relation, for example a kind base that is the sum of two other kind bases, lets a prover hide an imbalance in the delta proof. Points from hash to curve meet this condition. The in-circuit and out-of-circuit checks of arm-risc0 cover only the encoding of a kind base and that it is on the curve.

## 6. Parameters

| Name                                       | Value                                                                                                          |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| `PADDING_LEAF`, the root of the empty tree | `cc1d2f838445db7aec431df9ee8a871f40e7aa5e064fc056633ef8c60fab7b06` = `SHA-256("EMPTY")`                        |
| Leaf                                       | `SHA-256(logic_ref ‖ label_ref ‖ kind_base)`                                                                   |
| Kind base encoding                         | Uncompressed SEC1, 65 bytes, first byte `0x04`                                                                 |
| Hash to curve                              | RFC 9380 on secp256k1 over `logic_ref ‖ label_ref`, domain `QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_` |

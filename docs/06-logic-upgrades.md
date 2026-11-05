# Logic Upgrades

This document specifies how to replace a resource logic that has a vulnerability: an entry of the kind tree redirects a consumed resource from its old logic to a new logic, and the verifiers revoke the old logic. The code is in [`arm/src/compliance.rs`](../arm/src/compliance.rs) (`constrain`), [`arm/src/kind_tree.rs`](../arm/src/kind_tree.rs) and [`arm/src/transaction.rs`](../arm/src/transaction.rs) (`revoked_logic_check`).

## 1. The problem

A logic upgrade replaces the old logic ref of a kind with a new logic ref. Let `K_new` be the kind base of the new kind from hash to curve. The kind tree already supports the conversion of the kind ([`03-kind-tree.md`](./03-kind-tree.md)):

| Entry      | Pair                         | Kind base | Use                                                       |
| ---------- | ---------------------------- | --------- | --------------------------------------------------------- |
| Conversion | `(old_logic_ref, label_ref)` | `K_new`   | The old kind becomes an alias of the new kind             |
| New kind   | `(new_logic_ref, label_ref)` | `K_new`   | Optional: the circuit reads `K_new` without hash to curve |

A transaction can then consume resources of the old kind and create resources of the new kind for the same quantity, and the delta balances.

The conversion does not replace the old logic. Each entry of the compliance instance holds the logic ref of its resource, and the logic proof of each resource must have this logic ref as its verifying key. For a transaction with actions, the out-of-circuit check in `action::get_logic_verifiers` requires this. For an aggregated transaction, an in-circuit check of the aggregation circuit verifies each logic proof with the logic ref of the compliance instance, and its journal holds this logic ref. So each consumed resource of the old kind needs a proof of the old logic. If the old logic has a vulnerability, for example a missing check of the owner, an attacker can still use it, and no kind tree can stop this.

## 2. The proposal

The proposal has three parts:

1. **Redirect entry.** Each entry of the kind tree gets a target logic ref. The conversion entry becomes `(old_logic_ref, label_ref, new_logic_ref, K_new)`. Each other entry has its own logic ref as its target.
2. **Redirect in the circuit.** If a consumed resource has a kind path, `compliance::constrain` writes the target logic ref of the entry, not the logic ref of the resource, into its entry of the compliance instance. The existing checks then require a proof of the new logic for this nullifier: the out-of-circuit check for a transaction with actions, and the in-circuit check of the aggregation circuit for an aggregated transaction. The journal then holds the new logic ref for this nullifier.
3. **Revocation by the verifier.** Each verifier holds a set of revoked logic refs. An out-of-circuit check rejects a transaction if an entry of its compliance instances, or of its journal, holds a revoked logic ref.

The revocation makes the redirect necessary. Without a kind path, a consumed resource of the old kind keeps the old logic ref in the instance, and the verifier rejects it. A created resource never gets a redirect, so a transaction cannot create new resources of the old kind. The old logic never runs again.

The new logic then sets the rules for the consumption of resources of the old kind. It must accept a consumed resource whose logic ref is not its own, and whose label ref and value ref have the encoding of the old logic.

## 3. Changes to the compliance circuit

`KindTreeEntry` and `KindPath` get a field `target_logic_ref`. The leaf becomes:

```
SHA-256(logic_ref ‖ label_ref ‖ target_logic_ref ‖ kind_base)
```

Each leaf holds the target, also if it is equal to the logic ref. So a leaf of a redirect entry and a leaf of another entry never have the same encoding.

`compliance::constrain` uses these rules:

| Resource | Kind path | Logic ref in the instance | Additional in-circuit check                                      |
| -------- | --------- | ------------------------- | ---------------------------------------------------------------- |
| Consumed | None      | `resource.logic_ref`      | None                                                             |
| Consumed | Given     | `kp.target_logic_ref`     | The leaf contains `resource.logic_ref` and `kp.target_logic_ref` |
| Created  | None      | `resource.logic_ref`      | None                                                             |
| Created  | Given     | `resource.logic_ref`      | `kp.target_logic_ref` must equal `resource.logic_ref`            |

The last rule fails with `RedirectOnCreatedResource { position }`. The resolution of the kind base, the kind tree root of the unit and the delta do not change.

`KindTree::kind_path_for` copies the target into the kind path. The JSON file of a kind tree gets an optional field `target_logic_ref`, whose default is the logic ref, so the existing files stay valid. `KindTree::from_entries` still rejects two entries with the same pair, so each pair has exactly one target.

The aggregation circuit keeps its code. It verifies each logic proof with the logic ref of the compliance instance, so it requires a proof of the new logic for a redirected resource, and its journal holds the new logic ref. But the circuit is built with `anoma-rm-risc0`, whose types change, so it needs a new build with new values of `BATCH_AGGREGATION_VK` and `BATCH_AGGREGATION_EVM_VK`. Its journal holds the compliance verifying key. So the protocol adapters need the new `COMPLIANCE_VK` and the new aggregation verifying keys in the same upgrade.

## 4. Changes to the verifiers

- **`transaction::verify`.** The out-of-circuit check `transaction::revoked_logic_check(tx, revoked)` runs next to `transaction::kind_tree_root_check`. For an aggregated transaction it reads the logic refs from the journal (`AggregationResourceInstance::logic_ref`), else from the compliance instance of each action. A revoked logic ref makes it fail with `RevokedLogic { logic_ref }`. `transaction::verify` takes the revoked set as a parameter, as it takes the kind tree root, so a caller cannot leave the check out.
- **Protocol adapters.** The journal already holds the logic ref of each resource. Each protocol adapter stores a revoked set next to its kind tree root, and its out-of-circuit check rejects each logic ref in the set. Actually we already have the set on PA.

## 5. How one upgrade proceeds

1. The developers of the application deploy the new logic. A review compares its rules for the consumption of old resources with the rules of the old logic.
2. The authority builds a kind tree with the redirect entry `(old_logic_ref, label_ref, new_logic_ref, K_new)` for each label ref in use, and the entries `(new_logic_ref, label_ref, new_logic_ref, K_new)`.
3. In one change, the authority sets the new kind tree root and adds the old logic ref to the revoked set of each protocol adapter.
4. Owners consume their resources of the old kind with proofs of the new logic, and create resources of the new kind.

## 6. Trust assumptions

- **The authority over the kind tree root and the revoked set is honest.** With a redirect, the authority decides which logic may consume the resources of a kind. A redirect to a logic without checks lets anybody who knows the nullifier key consume those resources, and some applications share or publish their nullifier keys.
- **The new logic enforces the rules of the old logic for old resources.** No check of arm-risc0 compares the two logics.
- **The redirect and the revocation take effect together.** Before the revocation, the old logic still consumes old resources. After the revocation and before the redirect, nobody can consume them.

## 7. Consequences

- **The prover cannot choose the old logic.** Without the revocation, a prover leaves out the kind path and uses the old logic, so a redirect alone does not stop an attack.
- **A redirect covers all resources of a pair.** It cannot select single resources. A logic with many label refs needs one entry for each label ref in use.
- **Pending transactions fail.** A transaction with a proof of the old logic fails after the revocation.
- **Other parts see the new logic ref.** Indexers and calls of the protocol adapter that depend on the logic ref see the new logic ref for a nullifier of an old resource.

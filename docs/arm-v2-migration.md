# Bumping `anoma-rm-risc0` from `1.1.1` to `v2.0.0-rc.3-abi_encode`

Migration notes for **anomapay-backend-multichain** and **anomapay-workers-queue**.

- **From:** `anoma-rm-risc0 = "1.1.1"` (crates.io)
- **To:** `anoma-rm-risc0` @ git tag `v2.0.0-rc.3-abi_encode` (commit `a7d28eb`) —
  to be replaced by a published crates.io release before this ships

This is a **breaking major**. Almost every type the two services touch —
`Action`, `ComplianceWitness`, `ComplianceInstance`, `ComplianceUnit`,
`LogicVerifier`, `Transaction`, `DeltaInstance` — changed shape.

---

## Part 1 — What changed in arm-risc0

### 1. The action model: one compliance unit per action, N:M resources

The single biggest structural change.

| v1.1.1 | v2.0.0-rc.3 |
|---|---|
| `Action { compliance_units: Vec<ComplianceUnit>, .. }` | `Action { compliance_unit: ComplianceUnit, .. }` |
| One CU = exactly **1 consumed + 1 created** resource | One CU = **N consumed + M created** resources |
| `ComplianceInstance { consumed_nullifier, consumed_logic_ref, consumed_commitment_tree_root, created_commitment, created_logic_ref, delta_x, delta_y }` | `ComplianceInstance { consumed_publics: Vec<ConsumedResourcePublic>, created_publics: Vec<CreatedResourcePublic>, delta_x, delta_y, kind_table_commitment }` |
| `ComplianceWitness { consumed_resource, merkle_path, nf_key, created_resource, ephemeral_root, rcv }` | `ComplianceWitness { consumed_data: Vec<ConsumedResourceWitness>, created_resources: Vec<Resource>, ephemeral_root, rcv, kind_table }` |

New public types in `arm::resource`:

```rust
pub struct ConsumedResourceWitness { resource: Resource, cm_merkle_path: MerklePath, nf_key: NullifierKey }
pub struct ConsumedResourcePublic  { resource_nullifier: Digest, resource_logic_ref: Digest, commitment_tree_root: Digest }
pub struct CreatedResourcePublic   { resource_commitment: Digest, resource_logic_ref: Digest }
```

Constructor change:

```rust
// v1
ComplianceWitness::from_resources_with_path(consumed, nf_key, path, created)
// v2
ComplianceWitness::from_resources_with_ephemeral_root(&consumed_data, &created_resources, valid_root, kind_table)
ComplianceWitness::from_resources(&consumed_data, &created_resources, kind_table)  // uses INITIAL_ROOT
```

The per-field helpers on `ComplianceWitness` (`consumed_commitment()`,
`created_commitment()`, `consumed_nullifier(&cm)`, `consumed_commitment_tree_root()`,
`consumed_resource_logic()`, `created_resource_logic()`, `delta()`) are **all gone**.
The only entry point is `constrain() -> ComplianceInstance`.

**Consequences for tag ordering.** The canonical tag order of an action is now
`ComplianceInstance::tags()` = *all consumed nullifiers, then all created
commitments* — no longer interleaved `(consumed, created, consumed, created, …)`.
The action tree is built from that order, so **action tree roots change** for any
transaction with more than one resource pair, and `logic_verifier_inputs` must be
supplied in exactly that positional order. `Action::get_logic_verifiers()` and
`Transaction::aggregate()` now do **positional** matching (v1 did a `HashMap`/`find`
lookup by tag), and return `ArmError::TagNotFound` on mismatch.

`ComplianceInstanceWords` and `COMPLIANCE_INSTANCE_SIZE` were removed — the
instance is variable-size now.

### 2. Created-resource nonces are derived, not copied

v1 required `created.nonce == consumed.nullifier` (1:1). With N:M that no longer
works. v2 derives:

```rust
Resource::hash_nullifiers(&[Digest]) -> Result<Digest, ArmError>          // rejects empty
Resource::derive_nonce(index: u32, nullifiers_digest: Digest) -> [u8; 32]
Resource::derive_nonce_from_nullifiers(index: u32, &[Digest]) -> Result<[u8; 32], ArmError>
```

with domain separator `b"ARM_NONCE_DERIVATION"` and a big-endian index.
`ComplianceWitness::constrain()` re-derives every created resource's nonce and
fails with `ArmError::InvalidResourceNonce` on mismatch. Any host code that sets
`created.nonce = consumed_nullifier` must switch to `derive_nonce`.

### 3. Kind lookup table (skips `hash_to_curve` in the compliance circuit)

New `KindTableEntry { logic_ref, label_ref, kind_point }`, carried in
`ComplianceWitness::kind_table` and committed to as
`ComplianceInstance::kind_table_commitment` (SHA-256 over
`logic_ref ‖ label_ref ‖ kind_point` for every entry, in order).

New global loader in `arm::constants`:

```rust
init_kind_table_from_file(path: &Path) -> Result<(), ArmError>  // first call wins
global_kind_table()      -> &'static [KindTableEntry]
global_kind_table_hash() -> Option<&'static Digest>
kind_entry_for(table, resource) -> Option<KindTableEntry>       // lookup, falls back to hash_to_curve
```

Entries are `{ "logic_ref": "<hex>", "label_ref": "<hex>" }`; the kind point is
derived at load time via hash-to-curve so the file can't drift out of sync.
A starter `arm/data/kind_table.json` ships in the repo (padding logic + test logic).

**Operational impact:** `Transaction::verify()` now calls
`kind_table_commitment_check()`, which requires the global table to be loaded and
to match the commitment in every compliance unit. Without
`init_kind_table_from_file`, verification fails with `ArmError::KindTableNotLoaded`.
New error variants: `KindTableCommitmentMismatch`, `KindTableGlobalMismatch`,
`KindTableNotLoaded`, `KindTableLoadFailed`.

Measured payoff (Groth16-less succinct compliance bench, from `arm_circuits/compliance/README.md`):

| batch | no table | with table |
|---:|:--:|:--:|
| 1 | 2.125 s | 808.7 ms |
| 2 | 3.084 s | 844.7 ms |
| 4 | 6.320 s | 1.235 s |
| 8 | 11.464 s | 1.288 s |

### 4. Aggregation rewritten: in-circuit cross-checks + compact typed journal

**v1:** the host serialized every compliance instance, every logic instance and
every logic VK into the guest input; the journal was the raw
`(compliance_instances, compliance_vk, logic_instances, logic_vks)` tuple. Any
verifier had to re-derive that instance from the transaction and re-check the
compliance↔logic bindings itself.

**v2:** the guest receives one `AggregationWitness` and enforces the bindings
*inside* the circuit:

```rust
pub struct AggregationWitness { compliance_key: Digest, actions: Vec<ActionWitness> }
pub struct ActionWitness {
    compliance_instance: ComplianceInstance,
    consumed_app_data: Vec<AppData>,   // the only data not already in the instance
    created_app_data:  Vec<AppData>,
}
```

The guest reconstructs each `LogicInstance` from the compliance instance itself,
so three constraints hold *structurally* rather than by assertion:

| Constraint | Enforced by |
|---|---|
| A — tag matches nullifier/commitment | tag read from the compliance instance |
| B — root matches action tree root | root recomputed in-circuit from the compliance tags |
| C — VK matches `resource_logic_ref` | `resource_logic_ref` used directly as the `env::verify` key |

It also asserts `kind_table_commitment` equality across all actions, and rejects
an empty action set.

The journal is now a typed, compact struct:

```rust
pub struct AggregationInstance {
    compliance_key: Digest,
    kind_table_commitment: Digest,
    actions: Vec<ActionAggregated>,
}
pub struct ActionAggregated {
    consumed_publics: Vec<ConsumedResourceAggregated>,  // + app_data
    created_publics:  Vec<CreatedResourceAggregated>,   // + app_data
    delta_x: [u32; 8], delta_y: [u32; 8],
    action_tree_root: Digest,                            // computed in-circuit
}
```

Transaction shape follows:

```rust
// v1
pub struct Transaction { actions: Vec<Action>, delta_proof: Delta, expected_balance: Option<Vec<u8>>, aggregation_proof: Option<Vec<u8>> }
// v2
pub struct Aggregation  { proof: Vec<u8>, instance: AggregationInstance }
pub struct Transaction  { actions: Option<Vec<Action>>, delta_proof: Delta, expected_balance: Option<Vec<u8>>, aggregation: Option<Aggregation> }
```

`aggregate()` sets `aggregation = Some(..)` and **clears `actions` to `None`**
(v1 kept the actions and nulled each individual proof). `construct_aggregation_instance()`
is gone — the instance is decoded from the journal and stored.

New invariant, enforced by `Transaction::check_representation()`: a transaction
must carry **exactly one** of `actions` / `aggregation`. Both → `AmbiguousTransactionRepresentation`;
neither → `MissingActions`. When `aggregation` is present it is *authoritative* for
delta, nullifier and kind-table checks — deliberately, so a crafted transaction can't
pair a genuine aggregation proof with unverified attacker-controlled `actions`.
`verify_aggregation()` additionally pins `instance.compliance_key == COMPLIANCE_VK`.

`base_proofs_are_empty()` changed meaning: it is now simply `self.actions.is_none()`
(v1: "any individual proof is missing").

### 5. EVM ABI-encoded aggregation output — the `-abi_encode` delta

Everything above is in `v2.0.0-rc.3`. The `-abi_encode` tag is **purely additive on
top of it** (`arm/Cargo.toml` +3, one new ELF, `aggregation_instance.rs` +350,
`constants.rs` +10, `transaction.rs` +57/−14) and entirely behind a new opt-in
feature:

```toml
abi_encoding = ["dep:alloy-sol-types", "dep:alloy-primitives"]
```

- New guest ELF + image ID: `BATCH_AGGREGATION_EVM_PK`, `BATCH_AGGREGATION_EVM_VK = 0x4c0a771d29fce1983f108f4509552bb7f950c226f173f8d3244ef952dcde6978`.
- New `alloy` `sol!` mirror of the journal: `AggregationInstanceEvm` with
  `Action` / `Consumed` / `Created` / `Delta` / `AppData` / `ExpirableBlob`,
  plus `abi_encode_instance` / `abi_decode_instance`.
- With the feature on, `aggregate()` proves against the EVM guest and
  `verify_aggregation()` reconstructs the journal via `abi_encode_instance` and
  verifies against `BATCH_AGGREGATION_EVM_VK`. With it off, byte-identical
  behaviour to `v2.0.0-rc.3`.

Motivation: the EVM protocol adapter currently hand-rolls risc0-serde in Solidity
(`RiscZeroUtils.toJournal`, little-endian `u32` counts, raw digests). ABI encoding
lets the contract use native `abi.decode` instead.

Benchmarks (RTX 4090, Groth16, `prove,bonsai,cuda`) — ABI encoding is free:

| batch | v1 baseline | v2 default | v2 + `abi_encoding` |
|---:|:--:|:--:|:--:|
| 1 | 6.54 s | 6.43 s | 6.18 s |
| 2 | 8.59 s | 8.14 s | 8.02 s |
| 4 | 13.08 s | 12.18 s | 11.75 s |

### 6. Delta proof: message moved into the instance, message is action tree roots

```rust
// v1
pub struct DeltaInstance { verifying_key: VerifyingKey }
DeltaInstance::from_deltas(&[ProjectivePoint]) -> Result<_, _>
DeltaProof::verify(message: &[u8], proof: &DeltaProof, instance: DeltaInstance)

// v2
pub struct DeltaInstance { verifying_key: VerifyingKey, message: Vec<u8> }
DeltaInstance::new(&[ProjectivePoint], message: Vec<u8>) -> Result<_, _>
DeltaProof::verify(proof: &DeltaProof, instance: &DeltaInstance)
```

The **delta message changed**: v1 concatenated each compliance unit's
`delta_msg()` (its tags); v2 concatenates each action's **action tree root**
(32 bytes per action). `Transaction::get_delta_msg()` is now private.

Also in `delta_proof.rs`:
- `DeltaWitness::from_scalars`, `compose`, `compress` now return `Result` (were
  infallible / panicked); empty input → `ArmError::EmptyDeltaWitnesses`.
- `DeltaProof::from_bytes` validates length (65) and accepts both raw `{0,1}` and
  Ethereum `{27,28}` v-bytes; `to_bytes` still emits `{27,28}`.
- `DeltaWitness`'s `Deserialize` was fixed to match its `Serialize` (bincode
  round-trip was broken in v1 — it serialized as a seq and deserialized as `[u8; 32]`).

### 7. Proofs are no longer `Option`

```rust
// v1                          // v2
ComplianceUnit  { proof: Option<Vec<u8>>, .. }   →  { proof: Vec<u8>, .. }
LogicVerifier   { proof: Option<Vec<u8>>, .. }   →  { proof: Vec<u8>, .. }
LogicVerifierInput { proof: Option<Vec<u8>>, .. } → { proof: Vec<u8>, .. }
```

The `Option` existed only to model "erased after aggregation"; that state is now
`Transaction::actions == None`.

### 8. Renames, signature changes, hardening

- `action_tree::MerkleTree` → `action_tree::ActionTree` (and `generate_path` was
  de-recursed; new `padded_leaves` helper; unit tests added).
- `ComplianceWitness::merkle_path` → `ConsumedResourceWitness::cm_merkle_path`;
  logic-side paths are `action_tree_path`.
- `Transaction::verify(self)` → `verify(&self)`; `Action::verify(self)` → `verify(&self)`.
- `Transaction::compose` returns `Result<Transaction, ArmError>` instead of
  panicking on mismatched delta types; rejects already-aggregated inputs.
- `Action::get_compliance_units()` → `get_compliance_unit()`;
  `get_logic_verifier_inputs()` returns `&[…]` instead of `&Vec<…>`.
- `Transaction::aggregate()` is now gated on `aggregation` **and** `prove`.
- `proving_system::instance_to_journal<T: Serialize>()` added (inverse of `journal_to_instance`).
- `utils::bytes_to_words` switched from big-endian to native-endian, and now
  round-trips with `words_to_bytes` on any platform.
- `TrivialLogicWitness::constrain` returns `ArmError::InvalidPaddingResource`
  instead of `assert!`-panicking.
- New error variants: `EmptyNullifiers`, `IncompatibleDeltaTypes`,
  `EmptyDeltaWitnesses`, `InvalidPaddingResource`, `MissingActions`,
  `CannotComposeAggregated`, `AmbiguousTransactionRepresentation`, plus the four
  kind-table ones.
- `arm/src/lib.rs` re-exports `ActionAggregated`, `AggregationInstance`,
  `ConsumedResourceAggregated`, `CreatedResourceAggregated`.

### 9. Feature flags

| Feature | v1.1.1 | v2.0.0-rc.3-abi_encode |
|---|---|---|
| `default` | `transaction`, `prove` | unchanged |
| `transaction` | `compliance_circuit`, `dep:sha3` | unchanged |
| `aggregation` | `aggregation_circuit`, `transaction` | `transaction` |
| `aggregation_circuit` | ✅ | **removed** |
| `abi_encoding` | — | **new** (`alloy-sol-types`, `alloy-primitives`) |

### 10. New verifying keys / image IDs

The three circuits that ship *inside* arm were rebuilt, so their image IDs change:

| Key | v1.1.1 | v2.0.0-rc.3-abi_encode |
|---|---|---|
| `COMPLIANCE_VK` | `919e1300…86314d` | `88df64fe…9d8434` |
| `PADDING_LOGIC_VK` | `21fcc2fc…4a0bff` | `4527548f…7fea8f` |
| `BATCH_AGGREGATION_VK` | `213b3f40…b00827` | `5dc2615f…69058e` |
| `BATCH_AGGREGATION_EVM_VK` | — | `4c0a771d…de6978` |

**The app circuits are deliberately *not* rebuilt.** Transfer v1/v2 and generic-call
keep their existing ELFs and verifying keys; only the host-side libraries
(`transfer_library*`, `generic_call_library`) move to arm v2. This is already how
the two resource repos were bumped — `9b9076c` and `106f360` touch only
`Cargo.toml` / `Cargo.lock` (plus `migrate_tx.rs` and a new `kind_table.json`) and
leave `transfer_library/elf/` untouched. Those ELFs were last built against arm
**1.1.1** and stay that way.

That keeps the on-chain logic refs stable, and it is sound because nothing the
guest and host must agree on changed between 1.1.1 and 2.x:

- **Witness and instance layouts.** `logic_instance.rs` (`LogicInstance`,
  `AppData`, `ExpirableBlob`) and `nullifier_key.rs` are untouched by the diff;
  `Resource`'s field set and `MerklePath`'s representation are unchanged. Host and
  frozen guest serialize identically.
- **Resource derivations.** The `psi`/`rcm` refactor into `prf_expand` emits the
  same bytes (same personalization, same 1-byte discriminator, same seed, same
  nonce), and `kind()` just delegates to the new `generate_resource_kind`. So
  commitments, nullifiers and kinds are bit-identical.
- **`utils::bytes_to_words`.** The big-endian → native-endian rewrite looks like a
  behaviour change and is worth checking, because the app witness crates call it
  on `forwarder_call_data.encode()` inside `constrain()` — code that runs both in
  the frozen guest and on the rebuilt host. It is not: v1 computed
  `u32::from_be(from_be_bytes(chunk))`, which on a little-endian target is exactly
  `from_le_bytes(chunk)` — the same as v2's `from_ne_bytes(chunk)`. RISC-V and
  every host platform here are little-endian, so the two agree. The change only
  affects hypothetical big-endian builds.

Two things this does *not* excuse:

- **`PADDING_LOGIC_VK` is not frozen** — it ships from arm and did change
  (`TrivialLogicWitness::constrain` now returns `InvalidPaddingResource` instead of
  `assert!`-panicking, and the ELF was rebuilt). The kind table and anything
  on-chain referencing the padding logic ref must use `4527548f…`.
- **The freeze is implicit and can break silently.** The bump commits updated
  `transfer_circuit/methods/guest/Cargo.lock`, so the next `cargo risczero build`
  of those circuits will emit a *different* ELF and image ID than the checked-in
  constant, with nothing to catch it. Add a CI check that the built image ID
  equals the `Digest::from_hex(...)` in `transfer_library*/src/lib.rs`, or the
  freeze holds only by nobody happening to rebuild.

---

## Part 2 — Required changes in the two services (backend and worker queue)

### 2.0 Blockers that are not in either repo

These have to land first; neither service can compile without them.

1. **`anoma-rm-risc0` v2 is not on crates.io** — publish it soon. Until then both
   repos must move to a **git dependency**:

   ```toml
   anoma-rm-risc0 = { git = "https://github.com/anoma/arm-risc0", tag = "v2.0.0-rc.3-abi_encode", default-features = false }
   anoma-rm-risc0-gadgets = { git = "https://github.com/anoma/arm-risc0", tag = "v2.0.0-rc.3-abi_encode" }
   ```

   `anoma-rm-risc0-gadgets` has **no API change** — only the version bump.

2. **Every crate in the graph must pin the *same* git rev**, so re-pin the circuit
   repos and pa-evm. Cargo will not unify two git checkouts at different revs even
   though both declare version `2.0.0-rc.3` — you would get two `anoma-rm-risc0`
   crates, and a `Transaction` from one would not satisfy the other.

   | Repo | arm pin today | needs |
   |---|---|---|
   | `anomapay-erc20-resource` (`transfer_library`, `transfer_witness`, `*_v2`) | git tag `v2.0.0-rc.3` (`784fb37`) | re-pin to `v2.0.0-rc.3-abi_encode` |
   | `generic-call-resource` (`anoma-generic-call-library`/`-witness`) | git tag `v2.0.0-rc.3` | re-pin to `v2.0.0-rc.3-abi_encode` |
   | `pa-evm` (`anoma-pa-evm-bindings` 3.0.0-rc.2) | git rev `784fb37` | re-pin to `v2.0.0-rc.3-abi_encode` |

   All three are unpublished at their v2 state, so both services also need git deps
   for `transfer_library*`, `transfer_witness*`, `anoma-generic-call-*` and
   `anoma-pa-evm-bindings` — crates.io `transfer_library 2.0.0` and
   `anoma-pa-evm-bindings 3.0.0-rc.2` are still built against arm 1.1.1.

3. **`alloy` 1.x → 2.x** — *confirm with @Michael whether this is necessary.*
   The v2 PA bindings require `alloy 2.2.0`; backend-multichain is on `alloy 1.1.2`
   and workers-queue on `alloy 1.5`. `DynProvider`, `NamedChain`, contract instances
   and revert-decoding types do not cross the major boundary, so this is a separate,
   non-trivial sub-migration touching every provider/broadcast/simulation call site.

4. **Kind table + on-chain constants.** Decide the production kind table, ship it
   to every process, and make sure it hashes to the PA's stored
   `kindTableCommitment`. It must include every logic ref actually used
   (padding, transfer v1/v2, generic-call) and every token, not just arm's sample file.

---

### 2.1 `anomapay-backend-multichain`

#### `Cargo.toml` (workspace)
- `anoma-rm-risc0` / `anoma-rm-risc0-gadgets` → git tag (above).
- `transfer_library`, `transfer_library_v2`, `transfer_witness`, `transfer_witness_v2`
  → git deps on `anomapay-erc20-resource`.
- `anoma-generic-call-library`, `anoma-generic-call-witness` → git deps on `generic-call-resource`.
- `anoma-pa-evm-bindings` `2.3.0` → `3.x` (git on `pa-evm`).
- `alloy` `1.1.2` → `2.x`, `alloy-primitives` / `alloy-sol-types` to match.
- Feature sets `["transaction", "aggregation"]` stay valid (`aggregation_circuit` was never named here).

#### Decision: one N:M compliance unit per transaction

A transaction becomes exactly **one** compliance unit → **one** `Action` → **one**
action tree → **one** entry in the on-chain `Action[]`. This is the target shape
for everything below.

What it buys:

| | v1 (1:1 units) | v2 (single N:M unit) |
|---|---|---|
| Compliance proofs per tx | N (one per resource pair) | **1** |
| Base-proof jobs per tx | N + L | **1 + L** |
| Aggregation batch size | N actions | **1 action** (~6.2 s Groth16, flat) |
| Compliance proving cost | ~linear in N | ~flat with the kind table (1.29 s at 8 resources) |
| Delta message | concat of each unit's tags | a single 32-byte action tree root |
| Padding resources | required to make counts match | **no longer needed** |

That last row is a real simplification: `witness_data/mod.rs` documents trivial
resources as "padding used to balance a transaction… sending 1 resource to 2
people consumes 1 but creates 2, so a created padding resource is inserted."
An N:M unit has no count-matching requirement — `constrain()` iterates
`consumed_data` and `created_resources` independently and only the per-kind
quantity sums must balance. Padding resources are ephemeral and zero-quantity,
so dropping them changes no balance. Keep `PaddingResourceLogic` around (the
padding logic ref stays in the kind table), but stop inserting padding purely to
pair things up.

**Construction order is now a hard sequence.** Created nonces depend on the
consumed nullifiers, and created commitments depend on those nonces, so
`parameters.rs` must build in this order:

1. Fix the consumed resource order (it defines nullifier order, which feeds nonce
   derivation — it must be identical here and in the witness).
2. `nullifiers = consumed.map(|c| c.nullifier())`
3. `digest = Resource::hash_nullifiers(&nullifiers)?`
4. For each created resource at index `i`: `resource.nonce = Resource::derive_nonce(i as u32, digest)`
5. `commitments = created.map(|r| r.commitment())` — only valid after step 4
6. `action_tree = ActionTree::new([nullifiers…, commitments…].concat())`
7. Logic witnesses for all resources, all against that one root, in
   `[consumed…, created…]` order
8. One `ComplianceWitness` over all of them

#### `crates/transfer_web/src/proving/parameters.rs` — largest change
- `compliance_witnesses()` → `compliance_witness()` (singular). Today it `zip`s
  consumed × created × merkle-proof into one `ComplianceWitness` per pair;
  it becomes one witness built from `Vec<ConsumedResourceWitness>` (resource +
  `cm_merkle_path` + `nf_key`) and `Vec<Resource>`, plus the kind table.
  `JobContext::compliance_witnesses: Vec<_>` collapses to a single value.
- One `rcv` for the whole transaction, so `DeltaWitness::from_bytes_vec(&rcvs)`
  becomes `DeltaWitness::from_bytes(&rcv)`.
- All ephemeral consumed resources now share the unit's single `ephemeral_root`
  (previously one per pair — in practice all `INITIAL_ROOT`, so no behaviour change).
- `action_tree()`: leaves are currently interleaved
  `[nf₀, cm₀, nf₁, cm₁, …]`. Must become `[all nullifiers…, all commitments…]`,
  i.e. `ComplianceInstance::tags()` order. `MerkleTree` → `ActionTree`.
- `logic_witnesses()`: currently emits **created first, then consumed**. Must emit
  **consumed first, then created**, matching the tag order — `Action::new` and
  `aggregate()` now match positionally and will hard-fail otherwise.
- Created-resource nonces: replace `nonce = consumed_nullifier` with the
  `derive_nonce` sequence above.
- `generate_transaction()`: `Action::new(compliance_units, logic_proofs)` →
  a single `Action::new(compliance_unit, logic_proofs)`;
  `Transaction::create(vec![action], …)` keeps its one-element vec;
  `transaction.clone().verify()` → `transaction.verify()` (takes `&self` now).
- After `aggregate()`, `transaction.actions` is `None` — anything downstream that
  reads actions must read `transaction.aggregation.instance.actions` (length 1).
- `MAX_RESOURCES` now bounds N + M inside a single unit rather than the unit
  count; re-check the limit against the compliance segment size.

#### `crates/transfer_web/src/proving/simulation.rs` — needs a redesign
- `ComplianceUnit { proof: None }` / `LogicVerifier { proof: None }` →
  `proof: Vec::new()`.
- `Action::new(Vec<ComplianceUnit>, …)` → the single unit.
- **The bigger problem:** `From<Transaction> for IProtocolAdapter::Transaction` in
  the v2 bindings builds the sol transaction from `tx.aggregation.instance.actions`
  and `panic!`s when `aggregation` is `None`. A proofless simulation transaction
  has no aggregation. So the simulation path must construct an
  `AggregationInstance` directly — with the single `ActionAggregated` assembled
  from the constrained `ComplianceInstance` (`consumed_publics`/`created_publics`,
  `delta_x`, `delta_y`), each resource's logic `app_data`, and the locally computed
  `action_tree_root` — rather than going through `Transaction`.
- `instance_journal()` can be replaced by `proving_system::instance_to_journal()`.

#### `crates/transfer_web/src/protocol_adapter/evm.rs`
- `ProtocolAdapter::Transaction` → `IProtocolAdapter::Transaction`.
- `fill_proof_selectors()` must be rewritten: the v2 sol `Transaction` has no
  `logicVerifierInputs` / `complianceVerifierInputs` — there is a single
  `aggregationProof`. `_checkSelector` still reads `proof[0:4]`, so the 4-byte
  verifier selector now needs to prefix that one field.
- `transaction.actions.len()` still works (sol-side `Action[]`), but the elements
  are the new `Consumed`/`Created` shape.
- Revert decoding moves to alloy 2 APIs.

#### `crates/transfer_orchestrator/src/handlers/processing.rs`
- The per-witness invariant loop uses `compliance_witness.created_resource`,
  `.consumed_commitment()`, `.consumed_nullifier(&cm)`, `.created_commitment()`,
  `.delta()` — none exist in v2. Rewrite over `constrain()`'s
  `ComplianceInstance { consumed_publics, created_publics }`.
- The loop itself collapses: there is one witness, so the
  "nullifier consumed in multiple CUs" / "commitment created in multiple CUs"
  checks become duplicate checks *within* the single unit's
  `consumed_publics` / `created_publics`.
- The "created resource nonce must match consumed nullifier" check becomes a
  `derive_nonce` check (and `constrain()` already enforces it, so this can likely
  just be dropped in favour of surfacing `InvalidResourceNonce`).
- `compliance_witness.delta()` is gone; `constrain()` computes the delta and
  fails on a bad `rcv`, so calling `constrain()` once covers it.

#### `crates/transfer_orchestrator/src/handlers/base_proofs.rs`
- The compliance branch submits one job instead of N. `indexed_idempotency_key(tx_id, "compliance", i)`
  is now always `i = 0` — either keep the index for key stability or switch to an
  unindexed key, but do it deliberately: reused keys against the old worker would
  return v1-shaped results.

#### `crates/transfer_orchestrator/src/handlers/save_base_proofs.rs`
- `LogicVerifier { proof: Some(receipt) }` → `proof: receipt`;
  `ComplianceUnit { proof: Some(receipt) }` → `proof: receipt`.
- `Action::new(compliance_units, logic_proofs)` → `Action::new(compliance_unit, logic_proofs)`
  with the one unit from `ctx.compliance_proof_results`.
- **Ordering is now load-bearing:** `ctx.logic_proof_results` is filled by
  `try_join_all` over the submitted job ids, so it preserves submission order —
  that order must now equal `[consumed…, created…]`. Worth an explicit assertion
  against `compliance_instance.tags()` before building the action.
- `DeltaWitness::from_bytes_vec(&rcvs)` → `from_bytes(&rcv)` (single unit, single `rcv`).
- `Transaction::create(vec![action], …)` unchanged in signature.

#### `crates/transfer_orchestrator/src/handlers/context.rs`
- `compliance_witnesses: Vec<ComplianceWitness>` → a single `Option<ComplianceWitness>`;
  `compliance_proof_results: Vec<ComplianceUnit>` → `Option<ComplianceUnit>`.
  `require_compliance_witnesses` / `all_compliance_proofs_complete` follow.
- `logic_proof_results: Vec<LogicVerifier>` stays a vec, but now needs a documented
  order contract (`[consumed…, created…]`) since matching is positional.

#### `crates/transfer_orchestrator/src/services/queue.rs`
- No API break, but `to_vec(compliance_witness)` now serializes the new
  variable-size witness — the queue worker must be on the same arm rev.
- `COMPLIANCE_PK` bytes changed (new ELF) → all cached/idempotent base-proof
  results are invalidated.

#### Startup
- Call `anoma_rm_risc0::constants::init_kind_table_from_file(path)` in
  `transfer_app` before any verification, and ship the JSON in the Docker image.

#### Tests
- `MerkleTree` → `ActionTree` across `crates/transfer_web/src/tests/**`
  (`helpers.rs`, `proving/{mint,burn,split,transfer}.rs`, `proving/v2/*`,
  `queue_proving.rs`) and fix the leaf ordering in each.
- `queue_proving.rs`: `Action::new`, `ComplianceUnit { proof: Some }`,
  `LogicVerifier { proof: Some }`.
- `test/helpers/mocks.rs`, `test/handlers/validation_tx.rs`: same fixups.

---

### 2.2 `anomapay-workers-queue`

Much smaller arm surface — 4 files — but `bento` is a full rewrite.

#### `Cargo.toml` (workspace)
- `anoma-rm-risc0` / `-gadgets` → git tag.
- `anoma-pa-evm-bindings` `2.3.0` → `3.x` (git), `alloy` `1.5` → `2.x`,
  `alloy-chains` to match. Keep the `sppark = "=0.1.14"` pin.

#### `bento/src/lib.rs` — rewrite `aggregation_proof` and `finalize_transaction`
This crate reimplements `Transaction::aggregate()` so it can set
`segment_limit_po2`. The v1 guest ABI it writes (four separate `env.write` calls:
`compliance_instances_u32`, `compliance_key`, `lp_instances_u32`, `lp_vks`) no
longer exists.

- Drop `ComplianceInstanceWords` and `bytes_to_words` (`ComplianceInstanceWords`
  is gone).
- Build a single `AggregationWitness`. With one N:M unit per transaction its
  `actions` vec has exactly one element, but keep the loop — the guest, the
  journal and the on-chain `Action[]` are all still `Vec`-shaped, and composed
  transactions would carry more:
  ```rust
  AggregationWitness {
      compliance_key,
      actions: tx.actions.as_ref().ok_or(..)?.iter().map(|a| ActionWitness {
          compliance_instance: a.compliance_unit.get_instance()?,
          consumed_app_data: /* first n_consumed logic_verifier_inputs, in order */,
          created_app_data:  /* the rest, in order */,
      }).collect(),
  }
  ```
  and `env_builder.write(&witnesses)` once. Add assumptions from
  `a.compliance_unit.get_inner_receipt()` and each `lvi.get_inner_receipt()`.
  Mirror the tag/count assertions `Transaction::aggregate()` does (`tags.len() ==
  logic_verifier_inputs.len()`, positional tag equality) so a malformed job fails
  fast instead of producing a bad proof.
- Default proving key: `BATCH_AGGREGATION_PK` (or `BATCH_AGGREGATION_EVM_PK` if
  and when `abi_encoding` is adopted).
- `finalize_transaction`: decode the journal into `AggregationInstance`
  (`receipt.journal.decode()`, or `abi_decode_params` under `abi_encoding`), then
  ```rust
  transaction.aggregation = Some(Aggregation { proof: bincode::serialize(&receipt.inner)?, instance });
  transaction.actions = None;
  ```
  Note v1 serialized the whole `ProveInfo` into `aggregation_proof`; v2 stores the
  bincode of `InnerReceipt` only — the PA bindings' `encode_seal(&aggregation.proof)`
  depends on that.
- `base_proofs_are_empty()` now means `actions.is_none()`; the current
  early-return still reads correctly but the error text should change.

#### `protocol-adapter/src/lib.rs`
- `generated::protocol_adapter::ProtocolAdapter::{ProtocolAdapterInstance, Transaction as PaTransaction}`
  → `Transaction` now lives in `IProtocolAdapter`; keep `ProtocolAdapterInstance`
  from `ProtocolAdapter`.
- `PaTransaction::from(transaction)` now panics unless `tx.aggregation.is_some()`
  **and** the delta proof is `Delta::Proof` — add an explicit pre-check returning
  `BroadcastError::Deserialization`/`Fatal` rather than letting it panic in a worker.
- alloy 2 for `DynProvider`, `PendingTransactionBuilder`, `contract::Error`,
  `as_revert_data`, `ReceiptResponse`.

#### `queue/src/handlers/broadcast/{mod.rs,rpc.rs}`
- Type-compatible, but the test fixture
  `Transaction::create(vec![], Delta::Proof(DeltaProof { signature, recid }))`
  produces `actions: Some(vec![])`; if any test asserts on aggregation it needs the
  new shape. `DeltaProof` fields are unchanged.
- Gas estimation / simulation paths inherit the alloy 2 bump.

#### `shared/`, `sdk/`, `gpu-worker/`
- `AggregationProofPayload { batch_aggregation_pk, compliance_vk }` still fits.
  If the ABI variant is adopted later, add a flag (or let the backend send
  `BATCH_AGGREGATION_EVM_PK` as `batch_aggregation_pk`) — the worker must not be
  able to silently prove the wrong guest.
- `shared/src/codec.rs` fixtures unaffected.

---

## Follow up work

1. Re-pin `anomapay-erc20-resource`, `generic-call-resource` and `pa-evm` to
   `v2.0.0-rc.3-abi_encode`;
2. Agree the production kind table; regenerate the PA's `kindTableCommitment`;
   publish the JSON as a shared artifact.
3. Land the `alloy` 1 → 2 bump in both services as its own PR (no arm changes) —
   it is mechanically large and independent.
4. Bump arm in `anomapay-workers-queue` (`bento` rewrite + PA bindings). Smaller
   surface, and the backend depends on its behaviour.
5. Bump arm in `anomapay-backend-multichain`, collapsing to the single N:M unit:
   witness construction → nonce derivation → action tree ordering →
   logic-witness ordering → simulation → orchestrator handlers → tests.
6. Drop the count-balancing padding resources once the N:M unit is in and the
   end-to-end tests pass.
7. Check changes on the frontend.

### Cutover note

`Transaction` is bincode-serialized across the backend↔queue boundary and
persisted in the DB (`pre_aggregation_transaction`, job payloads). The v2 struct
is not wire-compatible with v1 — `actions` became `Option<Vec<Action>>` and
`aggregation_proof: Option<Vec<u8>>` became `aggregation: Option<Aggregation>`,
so old blobs fail to deserialize rather than degrading gracefully. Drain all
in-flight jobs before cutover, or version the payload. `COMPLIANCE_PK` also
changed, so any cached or idempotency-keyed base-proof results from before the
bump are invalid.

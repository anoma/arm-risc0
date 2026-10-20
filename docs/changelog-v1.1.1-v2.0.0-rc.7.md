# Change Log: v1.1.1 → v2.0.0-rc.7

## New Crates

- **`anoma-rm-core`** — New engine-agnostic crate extracted in four refactor waves. Holds resource types, nullifier-key types, the compliance data model, delta proof/witness bytes, and all engine-free logic. Consumers that only need data types can depend on `anoma-rm-core` without pulling in the zkVM.

- **`anoma-rm-solana`** — New Solana verification engine. Links against SBPF v3 via `solana-program` v1 (moved off v2). Adds a Solana SBF CI job and teaches `update_elfs.sh` the const-form verifying keys.

## New Features

- **Variable-size compliance unit** — compliance circuit no longer has a fixed resource count; the unit size is determined by the witness at proving time.
- **Kind lookup tree in compliance circuit** — skips `hash_to_curve` in-circuit; kind tree root is enforced on transaction verification.
- **EVM ABI-encoded aggregation output** — batch aggregation circuit can emit an EVM-compatible ABI-encoded journal.
- **Aggregation: in-circuit `LogicInstance` construction** — eliminates redundant witness data; compliance↔logic cross-checks moved into the aggregation guest.


## Breaking Changes

| Area | Change |
|------|--------|
| **`JournalEncoding`** | `abi_encoding` feature flag replaced by a `JournalEncoding` enum. The EVM ABI path is now selected at runtime, not compile time. The host-side `abi_encoding` feature was removed; the EVM path is unconditional in the host. |
| **`ComplianceInstance`** | Now commits the `kind_tree` root; tag order is preserved in the action tree. |
| **Delta message** | Delta proof uses action-tree roots as the delta message; `DeltaInstance` now carries the message internally. |
| **Kind tree** | Flat array replaced by a Merkle tree. |
| **Nonce derivation** | Domain separator added; index uses big-endian encoding; empty nullifiers rejected. |
| **`aggregation_circuit` feature** | adjust aggregation circuit accordingly |

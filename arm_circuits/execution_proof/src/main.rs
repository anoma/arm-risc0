#[cfg(feature = "prove")]
use anoma_rm_risc0::execution_proof::ExecutionProofWitness;

pub fn main() {
    #[cfg(feature = "prove")]
    {
        use anoma_rm_risc0::{
            constants::{BATCH_AGGREGATION_VK_BYTES, COMPLIANCE_VK_BYTES},
            execution_proof::TxInput,
            incremental_merkle_tree::IncrementalMerkleTree,
            indexed_merkle_tree::IndexedMerkleTree,
            proving_system::ProofType,
            transaction::{Delta, Transaction},
            CoreDeltaWitness, Digest, TransactionExt,
        };
        use anoma_rm_risc0_test_app::create_an_action_with_multiple_compliances;

        fn vk(bytes: &[u8; 32]) -> Digest {
            Digest::try_from(bytes.as_slice()).expect("vk bytes")
        }

        let (action, dw) = create_an_action_with_multiple_compliances(1, 0, ProofType::Succinct);
        let mut tx = Transaction::create(
            vec![action],
            Delta::Witness(CoreDeltaWitness(dw.to_bytes())),
        )
        .generate_delta_proof()
        .unwrap();
        tx.aggregate(ProofType::Succinct).unwrap();

        let mut nullifier_tree = IndexedMerkleTree::new();
        let mut nullifier_witnesses = Vec::new();
        for action in &tx.actions {
            for cu in action.get_compliance_units() {
                nullifier_witnesses.push(
                    nullifier_tree
                        .insert(cu.instance.consumed_nullifier)
                        .unwrap(),
                );
            }
        }

        let tx_info = TxInput::from_transaction(&tx).unwrap();
        let witness = ExecutionProofWitness {
            transactions: vec![tx_info],
            commitment_tree: IncrementalMerkleTree::new(3),
            old_nullifier_tree_root: IndexedMerkleTree::new().root(),
            nullifier_witnesses,
            batch_aggregation_vk: vk(&BATCH_AGGREGATION_VK_BYTES),
            compliance_vk: vk(&COMPLIANCE_VK_BYTES),
        };

        let t = std::time::Instant::now();
        prove(&witness, risc0_zkvm::ProverOpts::succinct()).unwrap();
        println!("proof generation time: {:?}", t.elapsed());
    }
}

/// Deserialises each transaction's aggregation receipt, registers it as an
/// assumption, writes the witness to the guest, and proves the execution circuit.
#[cfg(feature = "prove")]
pub fn prove(
    witness: &ExecutionProofWitness,
    proof_type: risc0_zkvm::ProverOpts,
) -> Result<risc0_zkvm::Receipt, Box<dyn std::error::Error>> {
    use execution_proof_methods::EXECUTION_PROOF_GUEST_ELF;
    use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, VerifierContext};

    let mut env_builder = ExecutorEnv::builder();

    for tx in &witness.transactions {
        let inner: InnerReceipt = bincode::deserialize(&tx.aggregation_proof)?;
        env_builder.add_assumption(inner);
    }

    let env = env_builder.write(witness)?.build()?;

    let receipt = default_prover()
        .prove_with_ctx(
            env,
            &VerifierContext::default(),
            EXECUTION_PROOF_GUEST_ELF,
            &proof_type,
        )?
        .receipt;

    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use anoma_rm_risc0::{
        constants::{BATCH_AGGREGATION_VK_BYTES, COMPLIANCE_VK_BYTES},
        execution_proof::{ExecutionProofInstance, ExecutionProofWitness, TxInput},
        incremental_merkle_tree::IncrementalMerkleTree,
        indexed_merkle_tree::IndexedMerkleTree,
        Digest,
    };

    fn vk(bytes: &[u8; 32]) -> Digest {
        Digest::try_from(bytes.as_slice()).expect("vk bytes")
    }

    fn empty_witness() -> ExecutionProofWitness {
        let nullifier_tree = IndexedMerkleTree::new();
        ExecutionProofWitness {
            transactions: vec![],
            commitment_tree: IncrementalMerkleTree::new(3),
            old_nullifier_tree_root: nullifier_tree.root(),
            nullifier_witnesses: vec![],
            batch_aggregation_vk: vk(&BATCH_AGGREGATION_VK_BYTES),
            compliance_vk: vk(&COMPLIANCE_VK_BYTES),
        }
    }

    // ── Structural tests (no prove feature required) ──────────────────────────

    #[test]
    fn witness_serde_roundtrip() {
        let witness = empty_witness();
        let encoded = bincode::serialize(&witness).unwrap();
        let decoded: ExecutionProofWitness = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.transactions.len(), 0);
        assert_eq!(decoded.nullifier_witnesses.len(), 0);
        assert_eq!(decoded.commitment_tree, witness.commitment_tree);
        assert_eq!(
            decoded.old_nullifier_tree_root,
            witness.old_nullifier_tree_root
        );
    }

    #[test]
    fn tx_info_serde_roundtrip() {
        // aggregation_proof is #[serde(skip)] so it is stripped from both
        // bincode and risc0 serde output.  The host reads it directly from
        // the in-memory TxInput before calling env_builder.write(), so it
        // never needs to cross any serialisation boundary.
        let tx_info = TxInput {
            actions: vec![],
            delta_proof: vec![0u8; 65],
            aggregation_proof: vec![1, 2, 3],
        };
        let encoded = bincode::serialize(&tx_info).unwrap();
        let decoded: TxInput = bincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded.delta_proof, tx_info.delta_proof);
        assert_eq!(decoded.aggregation_proof, Vec::<u8>::new());
    }

    #[test]
    fn instance_serde_roundtrip() {
        let d = |v: u32| Digest::new([v, 0, 0, 0, 0, 0, 0, 0]);
        let instance = ExecutionProofInstance {
            old_commitment_tree_root: d(1),
            old_nullifier_tree_root: d(2),
            new_commitment_root: d(3),
            new_nullifier_tree_root: d(4),
            consumed_resource_app_data: vec![],
            created_resource_app_data: vec![],
            batch_aggregation_vk: vk(&BATCH_AGGREGATION_VK_BYTES),
            compliance_vk: vk(&COMPLIANCE_VK_BYTES),
        };
        let encoded = bincode::serialize(&instance).unwrap();
        let decoded: ExecutionProofInstance = bincode::deserialize(&encoded).unwrap();
        assert_eq!(instance, decoded);
    }

    /// Verifies the pattern used in witness construction: one InsertionWitness
    /// per nullifier, threading roots through `InsertionWitness::apply`.
    #[test]
    fn nullifier_witnesses_thread_roots_correctly() {
        // Use arbitrary distinct digests as nullifiers — no real transaction needed.
        let nullifiers: Vec<Digest> = (1u32..=4)
            .map(|i| Digest::new([i, 0, 0, 0, 0, 0, 0, 0]))
            .collect();

        let mut nullifier_tree = IndexedMerkleTree::new();
        let mut current_root = nullifier_tree.root();

        for &nf in &nullifiers {
            let witness = nullifier_tree.insert(nf).unwrap();
            current_root = witness.apply(&nf, &current_root).unwrap();
        }

        // After applying all witnesses the threaded root must equal the tree root.
        assert_eq!(current_root, nullifier_tree.root());
    }

    /// Confirms that inserting duplicate nullifiers into the indexed tree fails,
    /// which is the property the circuit depends on for batch uniqueness.
    #[test]
    fn duplicate_nullifier_insertion_fails() {
        let nf = Digest::new([42, 0, 0, 0, 0, 0, 0, 0]);
        let mut nullifier_tree = IndexedMerkleTree::new();
        nullifier_tree.insert(nf).unwrap();
        assert!(nullifier_tree.insert(nf).is_err());
    }

    // ── Prove tests (require --features prove) ────────────────────────────────

    /// Proves an empty batch and checks that the committed instance records
    /// the correct (unchanged) tree roots.
    ///
    /// Run with: `RISC0_DEV_MODE=1 cargo test --features prove prove_empty_batch`
    #[cfg(feature = "prove")]
    #[test]
    fn prove_empty_batch() {
        let commitment_tree = IncrementalMerkleTree::new(3);
        let nullifier_tree = IndexedMerkleTree::new();
        let old_commitment_root = commitment_tree.root();
        let old_nullifier_root = nullifier_tree.root();

        let witness = ExecutionProofWitness {
            transactions: vec![],
            commitment_tree,
            old_nullifier_tree_root: old_nullifier_root,
            nullifier_witnesses: vec![],
            batch_aggregation_vk: vk(&BATCH_AGGREGATION_VK_BYTES),
            compliance_vk: vk(&COMPLIANCE_VK_BYTES),
        };

        let receipt = super::prove(&witness, risc0_zkvm::ProverOpts::succinct()).unwrap();

        let instance: ExecutionProofInstance = receipt.journal.decode().unwrap();
        // No transactions — both tree roots must be unchanged.
        assert_eq!(instance.old_commitment_tree_root, old_commitment_root);
        assert_eq!(instance.old_nullifier_tree_root, old_nullifier_root);
        assert_eq!(instance.new_commitment_root, old_commitment_root);
        assert_eq!(instance.new_nullifier_tree_root, old_nullifier_root);

        super::verify(&receipt).unwrap();
    }

    /// Verifying a valid receipt against the wrong image ID must fail.
    ///
    /// Run with: `RISC0_DEV_MODE=1 cargo test --features prove verify_rejects_wrong_image_id`
    #[cfg(feature = "prove")]
    #[test]
    fn verify_rejects_wrong_image_id() {
        let receipt = super::prove(&empty_witness(), risc0_zkvm::ProverOpts::succinct()).unwrap();
        // All-zeros is never a valid image ID.
        assert!(receipt.verify([0u32; 8]).is_err());
    }

    /// Proves a single aggregated transaction and checks that the committed
    /// roots differ from their initial values (one commitment and one nullifier
    /// were inserted).
    ///
    /// Run with:
    ///   RISC0_DEV_MODE=1 cargo test --features prove prove_single_aggregated_transaction
    #[cfg(feature = "prove")]
    #[test]
    fn prove_single_aggregated_transaction() {
        use anoma_rm_risc0::{proving_system::ProofType, TransactionExt};
        use anoma_rm_risc0_test_app::generate_test_transaction;

        let mut tx = generate_test_transaction(1, 1, ProofType::Succinct);
        tx.aggregate(ProofType::Succinct).unwrap();

        let mut nullifier_tree = IndexedMerkleTree::new();
        let mut nullifier_witnesses = Vec::new();
        for action in &tx.actions {
            for cu in action.get_compliance_units() {
                let w = nullifier_tree
                    .insert(cu.instance.consumed_nullifier)
                    .unwrap();
                nullifier_witnesses.push(w);
            }
        }

        let commitment_tree = IncrementalMerkleTree::new(3);
        let old_nullifier_root = IndexedMerkleTree::new().root();
        let old_commitment_root = commitment_tree.root();

        let tx_info = TxInput::from_transaction(&tx).unwrap();
        let witness = ExecutionProofWitness {
            transactions: vec![tx_info],
            commitment_tree,
            old_nullifier_tree_root: old_nullifier_root,
            nullifier_witnesses,
            batch_aggregation_vk: vk(&BATCH_AGGREGATION_VK_BYTES),
            compliance_vk: vk(&COMPLIANCE_VK_BYTES),
        };

        let receipt = super::prove(&witness, risc0_zkvm::ProverOpts::succinct()).unwrap();

        let instance: ExecutionProofInstance = receipt.journal.decode().unwrap();
        assert_eq!(instance.old_commitment_tree_root, old_commitment_root);
        assert_eq!(instance.old_nullifier_tree_root, old_nullifier_root);
        // After one compliance unit the trees must have advanced.
        assert_ne!(instance.new_commitment_root, old_commitment_root);
        assert_ne!(instance.new_nullifier_tree_root, old_nullifier_root);

        super::verify(&receipt).unwrap();
    }

    /// Proves a batch of two independent transactions and checks that
    /// `verify` accepts the receipt.
    ///
    /// Run with:
    ///   RISC0_DEV_MODE=1 cargo test --features prove prove_two_aggregated_transactions
    #[cfg(feature = "prove")]
    #[test]
    fn prove_two_aggregated_transactions() {
        use anoma_rm_risc0::{
            proving_system::ProofType,
            transaction::{Delta, Transaction},
            CoreDeltaWitness, TransactionExt,
        };
        use anoma_rm_risc0_test_app::create_an_action_with_multiple_compliances;

        // Build each transaction with a distinct nonce (0 and 1) so their
        // compliance units produce different resources and unique nullifiers.
        let t = std::time::Instant::now();
        let (action1, dw1) = create_an_action_with_multiple_compliances(1, 0, ProofType::Succinct);
        let mut tx1 = Transaction::create(
            vec![action1],
            Delta::Witness(CoreDeltaWitness(dw1.to_bytes())),
        )
        .generate_delta_proof()
        .unwrap();
        tx1.aggregate(ProofType::Succinct).unwrap();
        println!("tx1 generation time: {:?}", t.elapsed());

        let (action2, dw2) = create_an_action_with_multiple_compliances(1, 1, ProofType::Succinct);
        let mut tx2 = Transaction::create(
            vec![action2],
            Delta::Witness(CoreDeltaWitness(dw2.to_bytes())),
        )
        .generate_delta_proof()
        .unwrap();
        tx2.aggregate(ProofType::Succinct).unwrap();

        // Build nullifier insertion witnesses for all compliance units in batch order.
        let mut nullifier_tree = IndexedMerkleTree::new();
        let mut nullifier_witnesses = Vec::new();
        for tx in [&tx1, &tx2] {
            for action in &tx.actions {
                for cu in action.get_compliance_units() {
                    let w = nullifier_tree
                        .insert(cu.instance.consumed_nullifier)
                        .unwrap();
                    nullifier_witnesses.push(w);
                }
            }
        }

        let commitment_tree = IncrementalMerkleTree::new(3);
        let old_nullifier_root = IndexedMerkleTree::new().root();

        let tx_infos: Vec<TxInput> = [&tx1, &tx2]
            .iter()
            .map(|tx| TxInput::from_transaction(tx).unwrap())
            .collect();
        let witness = ExecutionProofWitness {
            transactions: tx_infos,
            commitment_tree,
            old_nullifier_tree_root: old_nullifier_root,
            nullifier_witnesses,
            batch_aggregation_vk: vk(&BATCH_AGGREGATION_VK_BYTES),
            compliance_vk: vk(&COMPLIANCE_VK_BYTES),
        };

        let t0 = std::time::Instant::now();
        let receipt = super::prove(&witness, risc0_zkvm::ProverOpts::succinct()).unwrap();
        println!("proof generation time: {:?}", t0.elapsed());

        let instance: ExecutionProofInstance = receipt.journal.decode().unwrap();
        assert_eq!(instance.old_nullifier_tree_root, old_nullifier_root);

        super::verify(&receipt).unwrap();
    }
}

// Updates the ELF binary and prints the image ID.
// Run with: cargo test --features prove print_execution_proof_elf_id -- --nocapture
#[ignore]
#[test]
fn print_execution_proof_elf_id() {
    use execution_proof_methods::{EXECUTION_PROOF_GUEST_ELF, EXECUTION_PROOF_GUEST_ID};

    std::fs::write(
        "../../arm/elfs/execution-proof-guest.bin",
        EXECUTION_PROOF_GUEST_ELF,
    )
    .expect("Failed to write execution proof guest ELF binary");

    use risc0_zkvm::sha::Digest;
    println!(
        "EXECUTION_PROOF_GUEST_ID: {:?}",
        Digest::from(EXECUTION_PROOF_GUEST_ID)
    );
}

/// Verifies a proved execution receipt against the expected image ID.
#[cfg(feature = "prove")]
pub fn verify(receipt: &risc0_zkvm::Receipt) -> Result<(), Box<dyn std::error::Error>> {
    use execution_proof_methods::EXECUTION_PROOF_GUEST_ID;
    receipt.verify(EXECUTION_PROOF_GUEST_ID)?;
    Ok(())
}

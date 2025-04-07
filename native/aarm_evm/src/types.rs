use alloy::sol;

sol! {
    struct Resource {
        bytes32 logicRef;
        bytes32 labelRef;
        bytes32 valueRef;
        bytes32 nullifierKeyCommitment;
        uint256 quantity;
        uint256 nonce;
        uint256 randSeed;
        bool ephemeral;
    }

    enum DeletionCriterion {
        Immediately,
        Never
    }

    struct ExpirableBlob {
        DeletionCriterion deletionCriterion;
        bytes blob;
    }

    struct TagAppDataPair {
        bytes32 tag;
        ExpirableBlob appData;
    }

    struct LogicInstance {
        bytes32 tag;
        bool isConsumed;
        bytes32[] consumed;
        bytes32[] created;
        ExpirableBlob tagSpecificAppData;
    }

    struct TagLogicProofPair {
        bytes32 tag;
        LogicRefProofPair pair;
    }

    struct LogicRefProofPair {
        bytes32 logicRef;
        bytes proof;
    }

    struct ComplianceUnit {
        bytes proof;
        ComplianceInstance instance;
        bytes32 verifyingKey;
    }

    struct ComplianceInstance {
        ConsumedRefs consumed;
        CreatedRefs created;
        uint256[2] unitDelta;
    }

    struct ConsumedRefs {
        bytes32 nullifierRef;
        bytes32 rootRef;
        bytes32 logicRef;
    }

    struct CreatedRefs {
        bytes32 commitmentRef;
        bytes32 logicRef;
    }

    struct FFICall {
        address untrustedWrapperContract;
        bytes input;
        bytes output;
    }

    struct WrapperResourceFFICallPair {
        Resource wrapperResource;
        FFICall ffiCall;
    }

    struct Action {
        bytes32[] commitments;
        bytes32[] nullifiers;
        TagLogicProofPair[] logicProofs;
        ComplianceUnit[] complianceUnits;
        TagAppDataPair[] tagAppDataPairs;
        WrapperResourceFFICallPair[] wrapperResourceFFICallPairs;
    }

    struct Transaction {
        bytes32[] roots;
        Action[] actions;
        bytes deltaProof;
    }

    interface IProtocolAdapter {
        /// @notice Executes a transaction by adding the commitments and nullifiers to the commitment tree and nullifier
        /// set, respectively.
        /// @param transaction The transaction to execute.
        function execute(Transaction calldata transaction) external;

        /// @notice Verifies a transaction by checking the delta, resource logic, and compliance proofs.
        /// @param transaction The transaction to verify.
        function verify(Transaction calldata transaction) external view;
    }

    interface ICommitmentAccumulator {
        /// @notice Returns the latest  commitment tree state root.
        /// @return root The latest commitment tree state root.
        function latestRoot() external view returns (bytes32 root);

        /// @notice Checks if a commitment tree state root exists.
        /// @param root The root to check.
        /// @return isContained Whether the root exists or not.
        function containsRoot(bytes32 root) external view returns (bool isContained);

        /// @notice Verifies a that a Merkle path (proof) and a commitment leaf reproduces the given root.
        /// @param root The root to reproduce.
        /// @param commitment The commitment leaf to proof inclusion in the tree for.
        /// @param siblings The siblings constituting the path from the leaf to the root.
        /// @param directionBits The direction bits indicating whether the siblings are left of right.
        function verifyMerkleProof(
            bytes32 root,
            bytes32 commitment,
            bytes32[] calldata siblings,
            uint256 directionBits
        )
            external
            view;

        /// @notice Returns the Merkle proof and associated root for a commitment leaf in the tree.
        /// @param commitment The commitment leaf to proof inclusion in the tree for.
        /// @return siblings The siblings constituting the path from the leaf to the root.
        /// @return directionBits The direction bits for the proof.
        function merkleProof(bytes32 commitment) external view returns (bytes32[] memory siblings, uint256 directionBits);
    }

    interface IBlobStorage {
        /// @notice Looks a blob up in the blob storage or reverts.
        /// @param blobHash The hash of the blob to lookup.
        /// @return blob The found blob.
        function lookupBlob(bytes32 blobHash) external view returns (bytes memory blob);
    }
}

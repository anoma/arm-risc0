use alloy::sol;

sol! {
    enum DeletionCriterion {
        Immediately,
        Never
    }

    struct ExpirableBlob {
        DeletionCriterion deletionCriterion;
        bytes blob;
    }

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

    struct Transaction {
        Action[] actions;
        // DeltaProof deltaProof
        bytes deltaProof;
    }

    struct Action {
        LogicProof[] logicProofs;
        ComplianceUnit[] complianceUnits;
        ResourceForwarderCalldataPair[] resourceCalldataPairs;
    }

    struct LogicProof {
        bytes proof;
        LogicInstance instance;
        bytes32 logicRef; // logicVerifyingKeyOuter;
    }

    struct LogicInstance {
        bytes32 tag;
        bool isConsumed;
        bytes32 root;
        bytes ciphertext;
        ExpirableBlob[] appData;
    }

    struct ComplianceUnit {
        bytes proof;
        ComplianceInstance instance;
    }

    struct ComplianceInstance {
        ConsumedRefs consumed;
        CreatedRefs created;
        uint256[2] unitDelta;
    }

    struct ConsumedRefs {
        bytes32 nullifier;
        bytes32 root;
        bytes32 logicRef;
    }

    struct CreatedRefs {
        bytes32 commitment;
        bytes32 logicRef;
    }

    struct ResourceForwarderCalldataPair {
        Resource carrier;
        ForwarderCalldata call;
    }

    struct ForwarderCalldata {
        address untrustedForwarder;
        bytes input;
        bytes output;
    }

    interface IProtocolAdapter {
        function execute(Transaction calldata transaction) external;
        function verify(Transaction calldata transaction) external view;
    }

    interface ICommitmentAccumulator {
        function latestRoot() external view returns (bytes32 root);
        function containsRoot(bytes32 root) external view returns (bool isContained);
        function verifyMerkleProof(bytes32 root, bytes32 commitment, bytes32[] calldata siblings, uint256 directionBits) external view;
        function merkleProof(bytes32 commitment) external view returns (bytes32[] memory siblings, uint256 directionBits);
    }

    interface IBlobStorage {
        function lookupBlob(bytes32 blobHash) external view returns (bytes memory blob);
    }
}

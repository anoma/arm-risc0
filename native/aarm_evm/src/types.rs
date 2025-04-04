use alloy::sol;

sol! {
    struct Resource {
        bytes32 logicRef;
        bytes32 labelRef;
        uint256 quantity;
        bytes32 valueRef;
        bool ephemeral;
        uint256 nonce;
        bytes32 nullifierKeyCommitment;
        uint256 randSeed;
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
}

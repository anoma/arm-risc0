//! Compact aggregation instance committed by the batch aggregation guest.

use crate::{error::ArmError, logic_instance::AppData, utils::words_to_bytes};
use k256::{elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, ProjectivePoint};
use risc0_zkp::core::digest::Digest;
use serde::{Deserialize, Serialize};

#[cfg(feature = "abi_encoding")]
pub use evm::{abi_decode_instance, abi_encode_instance, AggregationInstanceEvm};

/// The public output committed by the aggregation guest.
///
/// Contains all information needed by a verifier to check the aggregated
/// transaction without re-running the compliance↔logic cross-checks —
/// those are now enforced inside the guest circuit.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AggregationInstance {
    /// VK of the compliance circuit — single for the whole transaction.
    pub compliance_key: Digest,
    /// Shared across all actions; equality enforced in-circuit.
    pub kind_table_commitment: Digest,
    /// One entry per compliance unit / action.
    pub actions: Vec<ActionAggregated>,
}

/// Per-action aggregated public data.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ActionAggregated {
    /// Consumed resources with merged app_data.
    pub consumed_publics: Vec<ConsumedResourceAggregated>,
    /// Created resources with merged app_data.
    pub created_publics: Vec<CreatedResourceAggregated>,
    /// Delta x coordinate ([u32; 8] avoids risc0 padding issues).
    pub delta_x: [u32; 8],
    /// Delta y coordinate ([u32; 8] avoids risc0 padding issues).
    pub delta_y: [u32; 8],
    /// Merkle root of the action tree; computed inside the aggregation circuit.
    pub action_tree_root: Digest,
}

/// Consumed resource public data merged with its logic circuit app_data.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConsumedResourceAggregated {
    /// The resource's nullifier.
    pub resource_nullifier: Digest,
    /// The logic circuit VK that was verified for this resource.
    pub resource_logic_ref: Digest,
    /// Merkle root of the commitment tree in which the resource is included.
    pub commitment_tree_root: Digest,
    /// Application data emitted by the logic circuit.
    pub app_data: AppData,
}

/// Created resource public data merged with its logic circuit app_data.
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CreatedResourceAggregated {
    /// The resource's commitment.
    pub resource_commitment: Digest,
    /// The logic circuit VK that was verified for this resource.
    pub resource_logic_ref: Digest,
    /// Application data emitted by the logic circuit.
    pub app_data: AppData,
}

impl ActionAggregated {
    /// Decodes the stored delta_x/delta_y coordinates into a projective point.
    pub fn delta_projective(&self) -> Result<ProjectivePoint, ArmError> {
        let encoded = EncodedPoint::from_affine_coordinates(
            words_to_bytes(&self.delta_x).into(),
            words_to_bytes(&self.delta_y).into(),
            false,
        );
        ProjectivePoint::from_encoded_point(&encoded)
            .into_option()
            .ok_or(ArmError::InvalidDelta)
    }
}

fn encode_digest(out: &mut Vec<u8>, digest: &Digest) {
    for word in digest.as_words() {
        out.extend_from_slice(&word.to_le_bytes());
    }
}

fn encode_word_array(out: &mut Vec<u8>, words: &[u32; 8]) {
    for word in words {
        out.extend_from_slice(&word.to_le_bytes());
    }
}

impl AggregationInstance {
    /// Hand-rolled risc0-serde encoder, byte-equivalent to
    /// `risc0_zkvm::serde::to_vec(&self)` (the journal committed by the batch
    /// aggregation guest). Exists so verifiers that cannot link risc0-serde —
    /// such as the Solana protocol adapter's on-chain program — can re-derive
    /// the journal. Equivalence is pinned by the `journal_format` tests.
    pub fn to_journal(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_digest(&mut out, &self.compliance_key);
        encode_digest(&mut out, &self.kind_table_commitment);
        out.extend_from_slice(&(self.actions.len() as u32).to_le_bytes());
        for action in &self.actions {
            out.extend_from_slice(&(action.consumed_publics.len() as u32).to_le_bytes());
            for consumed in &action.consumed_publics {
                encode_digest(&mut out, &consumed.resource_nullifier);
                encode_digest(&mut out, &consumed.resource_logic_ref);
                encode_digest(&mut out, &consumed.commitment_tree_root);
                consumed.app_data.encode_journal(&mut out);
            }
            out.extend_from_slice(&(action.created_publics.len() as u32).to_le_bytes());
            for created in &action.created_publics {
                encode_digest(&mut out, &created.resource_commitment);
                encode_digest(&mut out, &created.resource_logic_ref);
                created.app_data.encode_journal(&mut out);
            }
            encode_word_array(&mut out, &action.delta_x);
            encode_word_array(&mut out, &action.delta_y);
            encode_digest(&mut out, &action.action_tree_root);
        }
        out
    }

    /// The delta message: the concatenation of each action's action tree root
    /// (32 bytes per action).
    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(self.actions.len() * 32);
        for action in &self.actions {
            msg.extend_from_slice(action.action_tree_root.as_bytes());
        }
        msg
    }

    /// Checks for nullifier duplication across all actions.
    pub fn nf_duplication_check(&self) -> Result<(), ArmError> {
        let mut seen_nullifiers = std::collections::HashSet::new();
        for action in &self.actions {
            for consumed in &action.consumed_publics {
                if !seen_nullifiers.insert(consumed.resource_nullifier) {
                    return Err(ArmError::NullifierDuplication);
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "abi_encoding")]
mod evm {
    use alloy_primitives::{FixedBytes, U256};
    use alloy_sol_types::sol;

    use crate::{
        aggregation_instance::{
            ActionAggregated, AggregationInstance, ConsumedResourceAggregated,
            CreatedResourceAggregated,
        },
        logic_instance::{AppData as NativeAppData, ExpirableBlob as NativeExpirableBlob},
        utils::{bytes_to_words, words_to_bytes},
    };
    use risc0_zkp::core::digest::Digest;

    sol! {
        /// @notice Deletion criterion type for expirable blobs.
        type DeletionCriterion is uint32;

        /// @notice The top-level aggregation instance committed by the batch aggregation guest.
        /// @param compliance_key The verifying key of the compliance circuit.
        /// @param kind_table_commitment The shared kind table commitment across all actions.
        /// @param actions One entry per compliance unit / action.
        struct AggregationInstanceEvm {
            bytes32 compliance_key;
            bytes32 kind_table_commitment;
            Action[] actions;
        }

        /// @notice The action object providing context separation between non-intersecting sets of resources. An action
        /// corresponds to one compliance unit constraining its consumed and created resources.
        /// @param consumed The public data of the consumed resources.
        /// @param created The public data of the created resources.
        /// @param unitDelta The action's delta value obtained from the underlying compliance unit.
        /// @param actionTreeRoot The root of the tree containing the tags of all resources present in the action.
        struct Action {
            Consumed[] consumed;
            Created[] created;
            Delta unitDelta;
            bytes32 actionTreeRoot;
        }

        /// @notice The public data of a consumed resource.
        /// @param nullifier The nullifier of the resource.
        /// @param logicRef The reference to (the verifying key of) the resource logic.
        /// @param commitmentTreeRoot The historical commitment tree root the resource's inclusion is proven against.
        /// @param appData The application data associated with the resource.
        struct Consumed {
            bytes32 nullifier;
            bytes32 logicRef;
            bytes32 commitmentTreeRoot;
            AppData appData;
        }

        /// @notice The public data of a created resource.
        /// @param commitment The commitment of the resource.
        /// @param logicRef The reference to (the verifying key of) the resource logic.
        /// @param appData The application data associated with the resource.
        struct Created {
            bytes32 commitment;
            bytes32 logicRef;
            AppData appData;
        }

        /// @notice The elliptic curve point representing the delta value of an action's compliance unit.
        /// @param x The x component of the point.
        /// @param y The y component of the point.
        struct Delta {
            uint256 x;
            uint256 y;
        }

        /// @notice A struct containing payloads of different kinds.
        /// @param resourcePayload A list of blobs for encoding plaintext info connected to resources.
        /// @param discoveryPayload A list of blobs for encoding data with public keys for discovery.
        /// @param externalPayload A list of blobs for encoding data connected with external calls.
        /// @param applicationPayload A list of blobs for application-specific purposes.
        struct AppData {
            ExpirableBlob[] resourcePayload;
            ExpirableBlob[] discoveryPayload;
            ExpirableBlob[] externalPayload;
            ExpirableBlob[] applicationPayload;
        }

        /// @notice A blob with a deletion criterion attached.
        /// @param deletionCriterion The deletion criterion.
        /// @param blob The bytes-encoded blob data.
        struct ExpirableBlob {
            DeletionCriterion deletionCriterion;
            bytes blob;
        }
    }

    fn digest_to_bytes32(d: &Digest) -> FixedBytes<32> {
        FixedBytes::from_slice(d.as_bytes())
    }

    fn words_to_u256(words: &[u32; 8]) -> U256 {
        let bytes: [u8; 32] = words_to_bytes(words)
            .try_into()
            .expect("delta coordinate is always 32 bytes");
        U256::from_be_bytes(bytes)
    }

    fn convert_expirable_blob(b: &NativeExpirableBlob) -> ExpirableBlob {
        ExpirableBlob {
            deletionCriterion: b.deletion_criterion,
            blob: words_to_bytes(&b.blob).to_vec().into(),
        }
    }

    fn convert_app_data(a: &NativeAppData) -> AppData {
        AppData {
            resourcePayload: a
                .resource_payload
                .iter()
                .map(convert_expirable_blob)
                .collect(),
            discoveryPayload: a
                .discovery_payload
                .iter()
                .map(convert_expirable_blob)
                .collect(),
            externalPayload: a
                .external_payload
                .iter()
                .map(convert_expirable_blob)
                .collect(),
            applicationPayload: a
                .application_payload
                .iter()
                .map(convert_expirable_blob)
                .collect(),
        }
    }

    impl From<AggregationInstance> for AggregationInstanceEvm {
        fn from(inst: AggregationInstance) -> Self {
            Self {
                compliance_key: digest_to_bytes32(&inst.compliance_key),
                kind_table_commitment: digest_to_bytes32(&inst.kind_table_commitment),
                actions: inst.actions.into_iter().map(convert_action).collect(),
            }
        }
    }

    impl From<AggregationInstanceEvm> for AggregationInstance {
        fn from(evm: AggregationInstanceEvm) -> Self {
            Self {
                compliance_key: bytes32_to_digest(evm.compliance_key),
                kind_table_commitment: bytes32_to_digest(evm.kind_table_commitment),
                actions: evm.actions.into_iter().map(evm_action_to_native).collect(),
            }
        }
    }

    fn bytes32_to_digest(fb: FixedBytes<32>) -> Digest {
        let words: [u32; 8] = bytes_to_words(&fb.0)
            .try_into()
            .expect("32 bytes → 8 words");
        Digest::from(words)
    }

    fn u256_to_words(n: U256) -> [u32; 8] {
        let bytes = n.to_be_bytes::<32>();
        bytes_to_words(&bytes)
            .try_into()
            .expect("32 bytes → 8 words")
    }

    fn evm_expirable_blob_to_native(b: ExpirableBlob) -> NativeExpirableBlob {
        NativeExpirableBlob {
            deletion_criterion: b.deletionCriterion,
            blob: bytes_to_words(&b.blob),
        }
    }

    fn evm_app_data_to_native(a: AppData) -> NativeAppData {
        NativeAppData {
            resource_payload: a
                .resourcePayload
                .into_iter()
                .map(evm_expirable_blob_to_native)
                .collect(),
            discovery_payload: a
                .discoveryPayload
                .into_iter()
                .map(evm_expirable_blob_to_native)
                .collect(),
            external_payload: a
                .externalPayload
                .into_iter()
                .map(evm_expirable_blob_to_native)
                .collect(),
            application_payload: a
                .applicationPayload
                .into_iter()
                .map(evm_expirable_blob_to_native)
                .collect(),
        }
    }

    fn evm_action_to_native(a: Action) -> ActionAggregated {
        ActionAggregated {
            consumed_publics: a
                .consumed
                .into_iter()
                .map(|c| ConsumedResourceAggregated {
                    resource_nullifier: bytes32_to_digest(c.nullifier),
                    resource_logic_ref: bytes32_to_digest(c.logicRef),
                    commitment_tree_root: bytes32_to_digest(c.commitmentTreeRoot),
                    app_data: evm_app_data_to_native(c.appData),
                })
                .collect(),
            created_publics: a
                .created
                .into_iter()
                .map(|c| CreatedResourceAggregated {
                    resource_commitment: bytes32_to_digest(c.commitment),
                    resource_logic_ref: bytes32_to_digest(c.logicRef),
                    app_data: evm_app_data_to_native(c.appData),
                })
                .collect(),
            delta_x: u256_to_words(a.unitDelta.x),
            delta_y: u256_to_words(a.unitDelta.y),
            action_tree_root: bytes32_to_digest(a.actionTreeRoot),
        }
    }

    /// ABI-encodes an [`AggregationInstance`] as an [`AggregationInstanceEvm`].
    pub fn abi_encode_instance(inst: AggregationInstance) -> Vec<u8> {
        use alloy_sol_types::SolValue;
        AggregationInstanceEvm::from(inst).abi_encode_params()
    }

    /// ABI-decodes bytes produced by [`abi_encode_instance`] back into an [`AggregationInstance`].
    pub fn abi_decode_instance(
        bytes: &[u8],
    ) -> Result<AggregationInstance, alloy_sol_types::Error> {
        use alloy_sol_types::SolValue;
        AggregationInstanceEvm::abi_decode_params(bytes).map(AggregationInstance::from)
    }

    fn convert_action(a: ActionAggregated) -> Action {
        Action {
            consumed: a
                .consumed_publics
                .iter()
                .map(|c| Consumed {
                    nullifier: digest_to_bytes32(&c.resource_nullifier),
                    logicRef: digest_to_bytes32(&c.resource_logic_ref),
                    commitmentTreeRoot: digest_to_bytes32(&c.commitment_tree_root),
                    appData: convert_app_data(&c.app_data),
                })
                .collect(),
            created: a
                .created_publics
                .iter()
                .map(|c| Created {
                    commitment: digest_to_bytes32(&c.resource_commitment),
                    logicRef: digest_to_bytes32(&c.resource_logic_ref),
                    appData: convert_app_data(&c.app_data),
                })
                .collect(),
            unitDelta: Delta {
                x: words_to_u256(&a.delta_x),
                y: words_to_u256(&a.delta_y),
            },
            actionTreeRoot: digest_to_bytes32(&a.action_tree_root),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::logic_instance::{AppData, ExpirableBlob as NativeExpirableBlob};
        use hex::FromHex;
        use risc0_zkp::core::digest::Digest;

        fn make_digest(byte: u8) -> Digest {
            Digest::from_hex(hex::encode([byte; 32])).unwrap()
        }

        fn sample_instance() -> AggregationInstance {
            AggregationInstance {
                compliance_key: make_digest(0x01),
                kind_table_commitment: make_digest(0x02),
                actions: vec![ActionAggregated {
                    consumed_publics: vec![ConsumedResourceAggregated {
                        resource_nullifier: make_digest(0x03),
                        resource_logic_ref: make_digest(0x04),
                        commitment_tree_root: make_digest(0x05),
                        app_data: AppData {
                            resource_payload: vec![NativeExpirableBlob {
                                deletion_criterion: 7,
                                blob: vec![0xDEADBEEFu32, 0xCAFEBABEu32],
                            }],
                            discovery_payload: vec![NativeExpirableBlob {
                                deletion_criterion: 0,
                                blob: vec![],
                            }],
                            external_payload: vec![],
                            application_payload: vec![],
                        },
                    }],
                    created_publics: vec![CreatedResourceAggregated {
                        resource_commitment: make_digest(0x06),
                        resource_logic_ref: make_digest(0x07),
                        app_data: AppData::new(),
                    }],
                    delta_x: [0x11223344u32; 8],
                    delta_y: [0x55667788u32; 8],
                    action_tree_root: make_digest(0x08),
                }],
            }
        }

        #[test]
        fn test_evm_conversion_roundtrip() {
            let original = sample_instance();
            let evm = AggregationInstanceEvm::from(original.clone());
            let recovered = AggregationInstance::from(evm);
            assert_eq!(original, recovered);
        }

        #[test]
        fn test_abi_encode_decode_roundtrip() {
            let original = sample_instance();
            let encoded = abi_encode_instance(original.clone());
            let recovered = abi_decode_instance(&encoded).unwrap();
            assert_eq!(original, recovered);
        }

        #[test]
        fn test_empty_instance_roundtrip() {
            let original = AggregationInstance {
                compliance_key: make_digest(0xAA),
                kind_table_commitment: make_digest(0xBB),
                actions: vec![],
            };
            let encoded = abi_encode_instance(original.clone());
            let recovered = abi_decode_instance(&encoded).unwrap();
            assert_eq!(original, recovered);
        }
    }
}

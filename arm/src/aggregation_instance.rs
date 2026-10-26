//! Host-engine operations on the aggregation instance (k256 delta-point
//! decoding, EVM ABI conversion). The instance types live in
//! `anoma-rm-core` and are re-exported here unchanged.

pub use arm_core::aggregation_instance::*;

use crate::{error::ArmError, utils::words_to_bytes};
use k256::{elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, ProjectivePoint};

pub use evm::{
    abi_decode_instance, abi_encode_instance, AggregationInstance as EvmAggregationInstance,
};

/// Decodes an action's stored delta_x/delta_y coordinates into a projective point.
pub fn delta_projective(action: &ActionAggregated) -> Result<ProjectivePoint, ArmError> {
    delta_projective_from_words(&action.delta_x, &action.delta_y)
}

/// Decodes delta coordinates stored as words into a projective point.
/// It fails if they are not a valid point.
pub(crate) fn delta_projective_from_words(
    x: &[u32; 8],
    y: &[u32; 8],
) -> Result<ProjectivePoint, ArmError> {
    let encoded = EncodedPoint::from_affine_coordinates(
        words_to_bytes(x).into(),
        words_to_bytes(y).into(),
        false,
    );
    ProjectivePoint::from_encoded_point(&encoded)
        .into_option()
        .ok_or(ArmError::InvalidDelta)
}

mod evm {
    use alloy_primitives::{FixedBytes, U256};
    use alloy_sol_types::sol;

    use crate::Digest;
    use crate::{
        aggregation_instance::{
            ActionAggregated, AggregationInstance as NativeAggregationInstance,
            AggregationResourceInstance,
        },
        logic_instance::{AppData as NativeAppData, ExpirableBlob as NativeExpirableBlob},
        utils::{bytes_to_words, words_to_bytes},
    };

    sol! {
        /// @notice Deletion criterion type for expirable blobs.
        type DeletionCriterion is uint32;

        /// @notice The top-level aggregation instance committed by the batch aggregation guest.
        /// @param complianceKey The verifying key of the compliance circuit.
        /// @param kindTreeRoot The shared kind tree Merkle root across all actions.
        /// @param actions One entry per compliance unit / action.
        struct AggregationInstance {
            bytes32 complianceKey;
            bytes32 kindTreeRoot;
            Action[] actions;
        }

        /// @notice The action object providing context separation between non-intersecting sets of resources. An action
        /// corresponds to one compliance unit constraining its consumed and created resources.
        /// @param resources The part of the aggregation instance for each consumed and created resource, in the order
        /// in which the protocol adapter processes them.
        /// @param unitDelta The action's delta value obtained from the underlying compliance unit.
        /// @param actionTreeRoot The root of the tree whose leaves are the tags of the action's resources, in the order
        /// of `resources`.
        struct Action {
            ResourceInstance[] resources;
            Delta unitDelta;
            bytes32 actionTreeRoot;
        }

        /// @notice The part of the aggregation instance for one resource: its compliance data and the app data of its
        /// logic proof.
        /// @param consumed Whether the resource is consumed.
        /// @param tag The tag of the resource: the nullifier of a consumed resource or the commitment of a created
        /// resource.
        /// @param logicRef The reference to (the verifying key of) the resource logic.
        /// @param commitmentTreeRoot The historical commitment tree root that a consumed resource's inclusion is
        /// proven against, or `bytes32(0)` for a created resource.
        /// @param appData The application data associated with the resource.
        struct ResourceInstance {
            bool consumed;
            bytes32 tag;
            bytes32 logicRef;
            bytes32 commitmentTreeRoot;
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

    /// ABI-encodes a [`NativeAggregationInstance`] as an [`AggregationInstance`].
    pub fn abi_encode_instance(instance: NativeAggregationInstance) -> Vec<u8> {
        use alloy_sol_types::SolValue;
        AggregationInstance::from(instance).abi_encode_params()
    }

    /// ABI-decodes bytes produced by [`abi_encode_instance`] back into a [`NativeAggregationInstance`].
    pub fn abi_decode_instance(
        bytes: &[u8],
    ) -> Result<NativeAggregationInstance, alloy_sol_types::Error> {
        use alloy_sol_types::SolValue;
        AggregationInstance::abi_decode_params(bytes).map(NativeAggregationInstance::from)
    }

    impl From<NativeAggregationInstance> for AggregationInstance {
        fn from(native: NativeAggregationInstance) -> Self {
            Self {
                complianceKey: digest_to_bytes32(&native.compliance_key),
                kindTreeRoot: digest_to_bytes32(&native.kind_tree_root),
                actions: native.actions.into_iter().map(Action::from).collect(),
            }
        }
    }

    impl From<AggregationInstance> for NativeAggregationInstance {
        fn from(evm: AggregationInstance) -> Self {
            Self {
                compliance_key: bytes32_to_digest(evm.complianceKey),
                kind_tree_root: bytes32_to_digest(evm.kindTreeRoot),
                actions: evm
                    .actions
                    .into_iter()
                    .map(ActionAggregated::from)
                    .collect(),
            }
        }
    }

    impl From<ActionAggregated> for Action {
        fn from(native: ActionAggregated) -> Self {
            Self {
                resources: native
                    .resource_instances
                    .into_iter()
                    .map(ResourceInstance::from)
                    .collect(),
                unitDelta: Delta {
                    x: words_to_u256(&native.delta_x),
                    y: words_to_u256(&native.delta_y),
                },
                actionTreeRoot: digest_to_bytes32(&native.action_tree_root),
            }
        }
    }

    impl From<Action> for ActionAggregated {
        fn from(evm: Action) -> Self {
            Self {
                resource_instances: evm
                    .resources
                    .into_iter()
                    .map(AggregationResourceInstance::from)
                    .collect(),
                delta_x: u256_to_words(evm.unitDelta.x),
                delta_y: u256_to_words(evm.unitDelta.y),
                action_tree_root: bytes32_to_digest(evm.actionTreeRoot),
            }
        }
    }

    impl From<AggregationResourceInstance> for ResourceInstance {
        fn from(native: AggregationResourceInstance) -> Self {
            Self {
                consumed: native.is_consumed(),
                tag: digest_to_bytes32(&native.tag()),
                logicRef: digest_to_bytes32(&native.logic_ref()),
                commitmentTreeRoot: digest_to_bytes32(
                    &native.commitment_tree_root().unwrap_or(Digest::ZERO),
                ),
                appData: AppData::from(match native {
                    AggregationResourceInstance::Consumed { app_data, .. } => app_data,
                    AggregationResourceInstance::Created { app_data, .. } => app_data,
                }),
            }
        }
    }

    impl From<ResourceInstance> for AggregationResourceInstance {
        fn from(evm: ResourceInstance) -> Self {
            let tag = bytes32_to_digest(evm.tag);
            let logic_ref = bytes32_to_digest(evm.logicRef);
            let app_data = NativeAppData::from(evm.appData);
            if evm.consumed {
                AggregationResourceInstance::Consumed {
                    nullifier: tag,
                    logic_ref,
                    commitment_tree_root: bytes32_to_digest(evm.commitmentTreeRoot),
                    app_data,
                }
            } else {
                AggregationResourceInstance::Created {
                    commitment: tag,
                    logic_ref,
                    app_data,
                }
            }
        }
    }

    impl From<NativeAppData> for AppData {
        fn from(native: NativeAppData) -> Self {
            Self {
                resourcePayload: native
                    .resource_payload
                    .into_iter()
                    .map(ExpirableBlob::from)
                    .collect(),
                discoveryPayload: native
                    .discovery_payload
                    .into_iter()
                    .map(ExpirableBlob::from)
                    .collect(),
                externalPayload: native
                    .external_payload
                    .into_iter()
                    .map(ExpirableBlob::from)
                    .collect(),
                applicationPayload: native
                    .application_payload
                    .into_iter()
                    .map(ExpirableBlob::from)
                    .collect(),
            }
        }
    }

    impl From<AppData> for NativeAppData {
        fn from(evm: AppData) -> Self {
            Self {
                resource_payload: evm
                    .resourcePayload
                    .into_iter()
                    .map(NativeExpirableBlob::from)
                    .collect(),
                discovery_payload: evm
                    .discoveryPayload
                    .into_iter()
                    .map(NativeExpirableBlob::from)
                    .collect(),
                external_payload: evm
                    .externalPayload
                    .into_iter()
                    .map(NativeExpirableBlob::from)
                    .collect(),
                application_payload: evm
                    .applicationPayload
                    .into_iter()
                    .map(NativeExpirableBlob::from)
                    .collect(),
            }
        }
    }

    impl From<NativeExpirableBlob> for ExpirableBlob {
        fn from(native: NativeExpirableBlob) -> Self {
            Self {
                deletionCriterion: native.deletion_criterion,
                blob: words_to_bytes(&native.blob).to_vec().into(),
            }
        }
    }

    impl From<ExpirableBlob> for NativeExpirableBlob {
        fn from(evm: ExpirableBlob) -> Self {
            Self {
                deletion_criterion: evm.deletionCriterion,
                blob: bytes_to_words(&evm.blob),
            }
        }
    }

    fn digest_to_bytes32(d: &Digest) -> FixedBytes<32> {
        FixedBytes::from_slice(d.as_bytes())
    }

    fn bytes32_to_digest(fb: FixedBytes<32>) -> Digest {
        let words: [u32; 8] = bytes_to_words(&fb.0)
            .try_into()
            .expect("32 bytes → 8 words");
        Digest::from(words)
    }

    fn words_to_u256(words: &[u32; 8]) -> U256 {
        let bytes: [u8; 32] = words_to_bytes(words)
            .try_into()
            .expect("delta coordinate is always 32 bytes");
        U256::from_be_bytes(bytes)
    }

    fn u256_to_words(n: U256) -> [u32; 8] {
        let bytes = n.to_be_bytes::<32>();
        bytes_to_words(&bytes)
            .try_into()
            .expect("32 bytes → 8 words")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::Digest;
        use hex::FromHex;

        fn make_digest(byte: u8) -> Digest {
            Digest::from_hex(hex::encode([byte; 32])).unwrap()
        }

        fn sample_instance() -> NativeAggregationInstance {
            NativeAggregationInstance {
                compliance_key: make_digest(0x01),
                kind_tree_root: make_digest(0x02),
                actions: vec![ActionAggregated {
                    resource_instances: vec![
                        AggregationResourceInstance::Created {
                            commitment: make_digest(0x06),
                            logic_ref: make_digest(0x07),
                            app_data: NativeAppData::new(),
                        },
                        AggregationResourceInstance::Consumed {
                            nullifier: make_digest(0x03),
                            logic_ref: make_digest(0x04),
                            commitment_tree_root: make_digest(0x05),
                            app_data: NativeAppData {
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
                        },
                    ],
                    delta_x: [0x11223344u32; 8],
                    delta_y: [0x55667788u32; 8],
                    action_tree_root: make_digest(0x08),
                }],
            }
        }

        #[test]
        fn test_evm_conversion_roundtrip() {
            let original = sample_instance();
            let evm = AggregationInstance::from(original.clone());
            let recovered = NativeAggregationInstance::from(evm);
            assert_eq!(original, recovered);
        }

        #[test]
        fn test_evm_conversion_marks_consumed_resources_and_writes_the_zero_root_for_created_ones()
        {
            let evm = AggregationInstance::from(sample_instance());
            let resources = &evm.actions[0].resources;
            assert!(!resources[0].consumed);
            assert_eq!(resources[0].commitmentTreeRoot, FixedBytes::ZERO);
            assert!(resources[1].consumed);
            assert_eq!(
                resources[1].commitmentTreeRoot,
                digest_to_bytes32(&make_digest(0x05))
            );
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
            let original = NativeAggregationInstance {
                compliance_key: make_digest(0xAA),
                kind_tree_root: make_digest(0xBB),
                actions: vec![],
            };
            let encoded = abi_encode_instance(original.clone());
            let recovered = abi_decode_instance(&encoded).unwrap();
            assert_eq!(original, recovered);
        }
    }
}

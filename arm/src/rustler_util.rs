#![cfg(feature = "nif")]
// This module defines conversions from Rust to Rustler.
// Some of these are obvious, but we expect Vec<u8> and so on to be encoded/decoded as Elixir binaries
// which Rustler does not do for us.
// So even when an encoding/decoding can be derived using the module attribute, it's probably a bad idea.
use crate::action::Action;
use crate::action_tree::MerkleTree;
use crate::compliance::{ComplianceInstance, ComplianceWitness};
use crate::compliance_unit::ComplianceUnit;
use crate::delta_proof::{DeltaProof, DeltaWitness};
use crate::logic_instance::{AppData, ExpirableBlob, LogicInstance};
use crate::logic_proof::{LogicVerifier, LogicVerifierInputs};
use crate::merkle_path::MerklePath;
use crate::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use crate::resource::Resource;
use crate::transaction::{Delta, Transaction};
use crate::utils::{bytes_to_words, words_to_bytes};
use bincode;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use k256::AffinePoint;
use risc0_zkvm::Digest;
use rustler::types::atom;
use rustler::types::map::map_new;
use rustler::{atoms, Binary, Decoder, Encoder, NifResult};
use rustler::{Env, Error, OwnedBinary, Term};
use serde::{Deserialize, Serialize};
use std::io::Write;

atoms! {
    at_true = "true",
    at_false = "false",
    at_value = "value",
    at_key = "key",
    at_proof = "proof",
    at_instance = "instance",
    at_struct = "__struct__",
    at_deletion_criteria = "deletion_criteria",
    at_blob = "blob",
    at_compliance_unit = "Elixir.Anoma.Arm.ComplianceUnit",
    at_expirable_blob = "Elixir.Anoma.Arm.ExpirableBlob",
    at_app_data = "Elixir.Anoma.Arm.AppData",
    at_resource_payload = "resource_payload",
    at_discovery_payload = "discovery_payload",
    at_external_payload = "external_payload",
    at_application_payload = "application_payload",
    at_logic_instance = "Anoma.Arm.LogicInstance",
    at_is_consumed = "is_consumed",
    at_root = "root",
    at_logic_verifier_inputs = "Elixir.Anoma.Arm.LogicVerifierInputs",
    at_tag = "tag",
    at_verifying_key = "verifying_key",
    at_app_data_key = "app_data",
    at_action = "Elixir.Anoma.Arm.Action",
    at_compliance_units = "compliance_units",
    at_logic_verifier_inputs_key = "logic_verifier_inputs",
    at_merkle_tree = "Elixir.Anoma.Arm.MerkleTree",
    at_leaves = "leaves",
    at_compliance_instance = "Elixir.Anoma.Arm.ComplianceInstance",
    at_consumed_nullifier = "consumed_nullifier",
    at_consumed_logic_ref = "consumed_logic_ref",
    at_consumed_commitment_tree_root = "consumed_commitment_tree_root",
    at_created_commitment = "created_commitment",
    at_created_logic_ref = "created_logic_ref",
    at_delta_x = "delta_x",
    at_delta_y = "delta_y",
    at_compliance_witness = "Elixir.Anoma.Arm.ComplianceWitness",
    at_consumed_resource = "consumed_resource",
    at_merkle_path = "merkle_path",
    at_ephemeral_root = "ephemeral_root",
    at_nf_key = "nf_key",
    at_created_resource = "created_resource",
    at_rcv = "rcv",
    at_resource = "Elixir.Anoma.Arm.Resource",
    at_logic_ref = "logic_ref",
    at_label_ref = "label_ref",
    at_quantity = "quantity",
    at_value_ref = "value_ref",
    at_is_ephemeral = "is_ephemeral",
    at_nonce = "nonce",
    at_nk_commitment = "nk_commitment",
    at_rand_seed = "rand_seed",
    at_delta_proof = "Elixir.Anoma.Arm.DeltaProof",
    at_aggregation_proof = "aggregation_proof",
    at_signature = "signature",
    at_recid = "recid",
    at_delta_witness = "Elixir.Anoma.Arm.DeltaWitness",
    at_signing_key = "signing_key",
    at_logic_verifier = "Elixir.Anoma.Arm.LogicVerifier",
    at_transaction = "Elixir.Anoma.Arm.Transaction",
    at_actions = "actions",
    at_delta_proof_field = "delta_proof",
    at_expected_balance = "expected_balance",
    at_witness = "witness"
}

//--------------------------------------------------------------------------------------------------
// Helpers for encoding

/// I run bincode deserialize but with the error being a rustler::Error
pub fn bincode_deserialize<T>(binary: &[u8]) -> NifResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    bincode::deserialize::<T>(binary).map_err(|e| Error::Term(Box::new(e.to_string())))
}

/// I run bincode serialize but with the error being a rustler::Error
pub fn bincode_serialize<T>(term: &T) -> NifResult<Vec<u8>>
where
    T: Serialize,
{
    bincode::serialize(term).map_err(|e| Error::Term(Box::new(e.to_string())))
}

pub trait RustlerEncoder {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>>;
}

pub trait RustlerDecoder<'a>: Sized + 'a {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self>;
}
impl<'a> RustlerDecoder<'a> for Binary<'a> {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        term.decode::<Binary<'a>>()
    }
}

impl<T> RustlerEncoder for Option<T>
where
    T: RustlerEncoder,
{
    fn rustler_encode<'c>(&self, env: Env<'c>) -> NifResult<Term<'c>> {
        match *self {
            Some(ref value) => value.rustler_encode(env),
            None => Ok(atom::nil().encode(env)),
        }
    }
}

impl<'a, T> RustlerDecoder<'a> for Option<T>
where
    T: RustlerDecoder<'a>,
{
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        if let Ok(term) = RustlerDecoder::rustler_decode(term) {
            Ok(Some(term))
        } else {
            let decoded_atom: atom::Atom = term.decode()?;
            if decoded_atom == atom::nil() {
                Ok(None)
            } else {
                Err(Error::BadArg)
            }
        }
    }
}

impl RustlerEncoder for Vec<u8> {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let mut erl_bin = OwnedBinary::new(self.len())
            .ok_or_else(|| Error::RaiseTerm(Box::new("could not create OwnedBinary")))?;
        let _ = erl_bin.as_mut_slice().write_all(&self.as_slice());
        Ok(erl_bin.release(env).to_term(env))
    }
}

impl<'a> RustlerDecoder<'a> for Vec<u8> {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        term.decode::<Binary>().map(|t| t.to_vec())
    }
}

impl RustlerEncoder for Vec<u32> {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let mut erl_bin: OwnedBinary = OwnedBinary::new(self.len() * 4)
            .ok_or_else(|| Error::RaiseTerm(Box::new("could not create OwnedBinary")))?;
        let bytes: &[u8] = words_to_bytes(self.as_slice());
        let _ = erl_bin.as_mut_slice().write_all(bytes);
        Ok(erl_bin.release(env).to_term(env))
    }
}

impl<'a> RustlerDecoder<'a> for Vec<u32> {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        term.decode::<Binary>()
            .map(|b| bytes_to_words(b.as_slice()))
    }
}

impl RustlerEncoder for Digest {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        self.as_words().to_vec().rustler_encode(env)
    }
}

impl<'a> RustlerDecoder<'a> for Digest {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let binary: Vec<u32> = term.decode()?;
        binary.try_into().map_err(|_| Error::BadArg)
    }
}

impl RustlerEncoder for AffinePoint {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        bincode_serialize(self)?.rustler_encode(env)
    }
}

impl<'a> RustlerDecoder<'a> for AffinePoint {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let binary: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        bincode_deserialize(&binary)
    }
}

impl RustlerEncoder for Signature {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        bincode_serialize(self)?.rustler_encode(env)
    }
}

impl<'a> RustlerDecoder<'a> for Signature {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let binary: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        bincode_deserialize(&binary)
    }
}

impl RustlerEncoder for RecoveryId {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let byte: u8 = self.to_byte();
        Ok(byte.encode(env))
    }
}

impl<'a> RustlerDecoder<'a> for RecoveryId {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let byte: u8 = term.decode()?;
        RecoveryId::from_byte(byte).ok_or_else(|| Error::Term(Box::new("RecoveryId")))
    }
}

impl RustlerEncoder for SigningKey {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let bytes = self.to_bytes();
        let bytez = bytes.to_vec();
        RustlerEncoder::rustler_encode(&bytez, env)
    }
}

impl<'a> RustlerDecoder<'a> for SigningKey {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let bytez: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        SigningKey::from_slice(&bytez).map_err(|_| Error::Term(Box::new("invalid SigningKey")))
    }
}

//--------------------------------------------------------------------------------------------------
// ComplianceUnit

impl RustlerEncoder for ComplianceUnit {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_compliance_unit().encode(env))?
            .map_put(at_proof().encode(env), self.proof.rustler_encode(env)?)?
            .map_put(
                at_instance().encode(env),
                self.instance.rustler_encode(env)?,
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for ComplianceUnit {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let proof_term = term.map_get(at_proof().encode(term.get_env()));
        let proof = RustlerDecoder::rustler_decode(proof_term?)?;
        let instance_term = term.map_get(at_instance().encode(term.get_env()));
        let instance: Vec<u8> = RustlerDecoder::rustler_decode(instance_term?)?;
        Ok(ComplianceUnit { proof, instance })
    }
}

impl Encoder for ComplianceUnit {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_e| env.error_tuple("failed to encode ComplianceUnit"))
    }
}

impl<'a> Decoder<'a> for ComplianceUnit {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        ComplianceUnit::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// ExpirableBlob

impl RustlerEncoder for ExpirableBlob {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_expirable_blob().encode(env))?
            .map_put(at_blob().encode(env), self.blob.rustler_encode(env)?)?
            .map_put(
                at_deletion_criteria().encode(env),
                self.deletion_criterion.encode(env),
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for ExpirableBlob {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let blob_term = term.map_get(at_blob().encode(term.get_env()));
        let blob: Vec<u32> = RustlerDecoder::rustler_decode(blob_term?)?;
        let deletion_criteria_term = term.map_get(at_deletion_criteria().encode(term.get_env()));
        let deletion_criterion: u32 = deletion_criteria_term?.decode()?;
        Ok(ExpirableBlob {
            blob,
            deletion_criterion,
        })
    }
}

impl Encoder for ExpirableBlob {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_e| env.error_tuple("failed to encode ExpirableBlob"))
    }
}

impl<'a> Decoder<'a> for ExpirableBlob {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        ExpirableBlob::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// AppData

impl RustlerEncoder for AppData {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_app_data().encode(env))?
            .map_put(
                at_resource_payload().encode(env),
                self.resource_payload.encode(env),
            )?
            .map_put(
                at_discovery_payload().encode(env),
                self.discovery_payload.encode(env),
            )?
            .map_put(
                at_external_payload().encode(env),
                self.external_payload.encode(env),
            )?
            .map_put(
                at_application_payload().encode(env),
                self.application_payload.encode(env),
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for AppData {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let resource_payload_term = term.map_get(at_resource_payload().encode(term.get_env()))?;
        let resource_payload = resource_payload_term.decode()?;
        let discovery_payload_term = term.map_get(at_discovery_payload().encode(term.get_env()))?;
        let discovery_payload = discovery_payload_term.decode()?;
        let external_payload_term = term.map_get(at_external_payload().encode(term.get_env()))?;
        let external_payload = external_payload_term.decode()?;
        let app_payload_term = term.map_get(at_application_payload().encode(term.get_env()))?;
        let application_payload = app_payload_term.decode()?;

        Ok(AppData {
            resource_payload,
            discovery_payload,
            external_payload,
            application_payload,
        })
    }
}

impl Encoder for AppData {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_e| env.error_tuple("failed to encode AppData"))
    }
}

impl<'a> Decoder<'a> for AppData {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        AppData::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// LogicVerifierInputs

impl RustlerEncoder for LogicVerifierInputs {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(
                at_struct().encode(env),
                at_logic_verifier_inputs().encode(env),
            )?
            .map_put(at_tag().encode(env), self.tag.rustler_encode(env)?)?
            .map_put(
                at_verifying_key().encode(env),
                self.verifying_key.rustler_encode(env)?,
            )?
            .map_put(at_app_data_key().encode(env), self.app_data.encode(env))?
            .map_put(at_proof().encode(env), self.proof.rustler_encode(env)?)?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for LogicVerifierInputs {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let tag_term = term.map_get(at_tag().encode(term.get_env()))?;
        let tag = RustlerDecoder::rustler_decode(tag_term)?;
        let verifying_key_term = term.map_get(at_verifying_key().encode(term.get_env()))?;
        let verifying_key = RustlerDecoder::rustler_decode(verifying_key_term)?;
        let app_data_term = term.map_get(at_app_data_key().encode(term.get_env()))?;
        let app_data: AppData = app_data_term.decode()?;
        let proof_term = term.map_get(at_proof().encode(term.get_env()))?;
        let proof = RustlerDecoder::rustler_decode(proof_term)?;

        Ok(LogicVerifierInputs {
            tag,
            verifying_key,
            app_data,
            proof,
        })
    }
}

impl RustlerEncoder for LogicInstance {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        map_new(env)
            .map_put(at_struct().encode(env), at_logic_instance().encode(env))?
            .map_put(at_tag().encode(env), self.tag.rustler_encode(env)?)?
            .map_put(at_is_consumed().encode(env), self.is_consumed.encode(env))?
            .map_put(at_root().encode(env), self.root.rustler_encode(env)?)?
            .map_put(
                at_app_data().encode(env),
                self.app_data.rustler_encode(env)?,
            )
    }
}

impl<'a> RustlerDecoder<'a> for LogicInstance {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let env = term.get_env();

        let tag_term = term.map_get(at_tag().encode(env))?;
        let tag = RustlerDecoder::rustler_decode(tag_term)?;

        let is_consumed_term = term.map_get(at_is_consumed().encode(env))?;
        let is_consumed: bool = is_consumed_term.decode()?;

        let root_term = term.map_get(at_root().encode(env))?;
        let root = RustlerDecoder::rustler_decode(root_term)?;

        let app_data_term = term.map_get(at_app_data().encode(env))?;
        let app_data = RustlerDecoder::rustler_decode(app_data_term)?;

        Ok(LogicInstance {
            tag,
            is_consumed,
            root,
            app_data,
        })
    }
}

impl Encoder for LogicVerifierInputs {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode LogicVerifierInputs"))
    }
}

impl<'a> Decoder<'a> for LogicVerifierInputs {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        LogicVerifierInputs::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// Action

impl RustlerEncoder for Action {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_action().encode(env))?
            .map_put(
                at_compliance_units().encode(env),
                self.compliance_units.encode(env),
            )?
            .map_put(
                at_logic_verifier_inputs_key().encode(env),
                self.logic_verifier_inputs.encode(env),
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for Action {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let compliance_units_term = term.map_get(at_compliance_units().encode(term.get_env()))?;
        let compliance_units: Vec<ComplianceUnit> = compliance_units_term.decode()?;
        let logic_verifier_inputs_term =
            term.map_get(at_logic_verifier_inputs_key().encode(term.get_env()))?;
        let logic_verifier_inputs: Vec<LogicVerifierInputs> =
            logic_verifier_inputs_term.decode()?;

        Ok(Action {
            compliance_units,
            logic_verifier_inputs,
        })
    }
}

impl Encoder for Action {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_e| env.error_tuple("failed to encode Action"))
    }
}

impl<'a> Decoder<'a> for Action {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        Action::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// MerkleTree

impl RustlerEncoder for MerkleTree {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        // encode the leaves separately.
        // each leaf is a vec<u32> and we have to encode those as a binary individually.
        let encoded_vec: Term = self
            .leaves
            .iter()
            .map(|leaf| leaf.rustler_encode(env))
            .collect::<NifResult<Vec<Term>>>()?
            .encode(env);

        let map = map_new(env)
            .map_put(at_struct().encode(env), at_merkle_tree().encode(env))?
            .map_put(at_leaves().encode(env), encoded_vec)?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for MerkleTree {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let leaves_term = term.map_get(at_leaves().encode(term.get_env()))?;
        let leaves_terms = Vec::<Term>::decode(leaves_term)?;

        let leaves: Vec<Digest> = leaves_terms
            .iter()
            .map(|term| RustlerDecoder::rustler_decode(*term))
            .collect::<NifResult<Vec<_>>>()?;

        Ok(MerkleTree { leaves })
    }
}

impl Encoder for MerkleTree {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_e| env.error_tuple("failed to encode MerkleTree"))
    }
}

impl<'a> Decoder<'a> for MerkleTree {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        MerkleTree::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// MerklePath

impl RustlerEncoder for MerklePath {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let encoded_vec: Vec<Term> = self
            .0
            .iter()
            .map(|(hash, is_right)| {
                Ok((hash.rustler_encode(env)?, is_right.encode(env)).encode(env))
            })
            .collect::<NifResult<Vec<Term>>>()?;

        Ok(encoded_vec.encode(env))
    }
}

impl<'a> RustlerDecoder<'a> for MerklePath {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        Vec::<Term>::decode(term)?
            .iter()
            .map(|term| {
                let tuple: (Term, Term) = term.decode()?;
                let hash: Digest = RustlerDecoder::rustler_decode(tuple.0)?;
                let is_right: bool = tuple.1.decode()?;
                Ok((hash, is_right))
            })
            .collect::<NifResult<Vec<(Digest, bool)>>>()
            .map(MerklePath)
    }
}

impl Encoder for MerklePath {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_e| env.error_tuple("failed to encode MerklePath"))
    }
}

impl<'a> Decoder<'a> for MerklePath {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        MerklePath::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// ComplianceInstance

impl RustlerEncoder for ComplianceInstance {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(
                at_struct().encode(env),
                at_compliance_instance().encode(env),
            )?
            .map_put(
                at_consumed_nullifier().encode(env),
                self.consumed_nullifier.rustler_encode(env)?,
            )?
            .map_put(
                at_consumed_logic_ref().encode(env),
                self.consumed_logic_ref.rustler_encode(env)?,
            )?
            .map_put(
                at_consumed_commitment_tree_root().encode(env),
                self.consumed_commitment_tree_root.rustler_encode(env)?,
            )?
            .map_put(
                at_created_commitment().encode(env),
                self.created_commitment.rustler_encode(env)?,
            )?
            .map_put(
                at_created_logic_ref().encode(env),
                self.created_logic_ref.rustler_encode(env)?,
            )?
            .map_put(
                at_delta_x().encode(env),
                self.delta_x.to_vec().rustler_encode(env)?,
            )?
            .map_put(
                at_delta_y().encode(env),
                self.delta_y.to_vec().rustler_encode(env)?,
            )?;
        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for ComplianceInstance {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let consumed_nullifier_term =
            term.map_get(at_consumed_nullifier().encode(term.get_env()))?;
        let consumed_nullifier = RustlerDecoder::rustler_decode(consumed_nullifier_term)?;

        let consumed_logic_ref_term =
            term.map_get(at_consumed_logic_ref().encode(term.get_env()))?;
        let consumed_logic_ref = RustlerDecoder::rustler_decode(consumed_logic_ref_term)?;

        let consumed_commitment_tree_root_term =
            term.map_get(at_consumed_commitment_tree_root().encode(term.get_env()))?;
        let consumed_commitment_tree_root =
            RustlerDecoder::rustler_decode(consumed_commitment_tree_root_term)?;

        let created_commitment_term =
            term.map_get(at_created_commitment().encode(term.get_env()))?;
        let created_commitment = RustlerDecoder::rustler_decode(created_commitment_term)?;

        let created_logic_ref_term = term.map_get(at_created_logic_ref().encode(term.get_env()))?;
        let created_logic_ref = RustlerDecoder::rustler_decode(created_logic_ref_term)?;

        let delta_x_term = term.map_get(at_delta_x().encode(term.get_env()))?;
        let delta_x: Vec<u32> = RustlerDecoder::rustler_decode(delta_x_term)?;

        let delta_y_term = term.map_get(at_delta_y().encode(term.get_env()))?;
        let delta_y: Vec<u32> = RustlerDecoder::rustler_decode(delta_y_term)?;
        Ok(ComplianceInstance {
            consumed_nullifier,
            consumed_logic_ref,
            consumed_commitment_tree_root,
            created_commitment,
            created_logic_ref,
            delta_x: <[u32; 8]>::try_from(delta_x).map_err(|_e| Error::BadArg)?,
            delta_y: <[u32; 8]>::try_from(delta_y).map_err(|_e| Error::BadArg)?,
        })
    }
}

impl Encoder for ComplianceInstance {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode compliance instance"))
    }
}

impl<'a> Decoder<'a> for ComplianceInstance {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        ComplianceInstance::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// ComplianceWitness

impl RustlerEncoder for ComplianceWitness {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_compliance_witness().encode(env))?
            .map_put(
                at_consumed_resource().encode(env),
                self.consumed_resource.encode(env),
            )?
            .map_put(
                at_merkle_path().encode(env),
                self.merkle_path.rustler_encode(env)?,
            )?
            .map_put(
                at_ephemeral_root().encode(env),
                self.ephemeral_root.rustler_encode(env)?,
            )?
            .map_put(at_nf_key().encode(env), self.nf_key.encode(env))?
            .map_put(
                at_created_resource().encode(env),
                self.created_resource.encode(env),
            )?
            .map_put(at_rcv().encode(env), self.rcv.rustler_encode(env)?)?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for ComplianceWitness {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let consumed_resource_term = term.map_get(at_consumed_resource().encode(term.get_env()))?;
        let consumed_resource: Resource = consumed_resource_term.decode()?;

        let merkle_path_term = term.map_get(at_merkle_path().encode(term.get_env()))?;
        let merkle_path: MerklePath = RustlerDecoder::rustler_decode(merkle_path_term)?;

        let ephemeral_root_term = term.map_get(at_ephemeral_root().encode(term.get_env()))?;
        let ephemeral_root = RustlerDecoder::rustler_decode(ephemeral_root_term)?;

        let nf_key_term = term.map_get(at_nf_key().encode(term.get_env()))?;
        let nf_key: NullifierKey = nf_key_term.decode()?;

        let created_resource_term = term.map_get(at_created_resource().encode(term.get_env()))?;
        let created_resource: Resource = created_resource_term.decode()?;

        let rcv_term = term.map_get(at_rcv().encode(term.get_env()))?;
        let rcv: Vec<u8> = RustlerDecoder::rustler_decode(rcv_term)?;

        Ok(ComplianceWitness {
            consumed_resource,
            merkle_path,
            ephemeral_root,
            nf_key,
            created_resource,
            rcv,
        })
    }
}

impl Encoder for ComplianceWitness {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode compliance witness"))
    }
}

impl<'a> Decoder<'a> for ComplianceWitness {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        ComplianceWitness::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// NullifierKeyCommitment

impl RustlerEncoder for NullifierKeyCommitment {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let inner_bytes = self.inner().as_words().to_vec();
        inner_bytes.rustler_encode(env)
    }
}

impl<'a> RustlerDecoder<'a> for NullifierKeyCommitment {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let bytes: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        Ok(NullifierKeyCommitment::from_bytes(&bytes)
            .map_err(|e| Error::Term(Box::new(e.to_string())))?)
    }
}

impl Encoder for NullifierKeyCommitment {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode nullifier"))
    }
}

impl<'a> Decoder<'a> for NullifierKeyCommitment {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        NullifierKeyCommitment::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// NullifierKey

impl RustlerEncoder for NullifierKey {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let inner_bytes = self.inner().to_vec();
        inner_bytes.rustler_encode(env)
    }
}

impl<'a> RustlerDecoder<'a> for NullifierKey {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let bytes: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        Ok(NullifierKey::from_bytes(&bytes))
    }
}

impl Encoder for NullifierKey {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode NullifierKey"))
    }
}

impl<'a> Decoder<'a> for NullifierKey {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        NullifierKey::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// Resource

impl RustlerEncoder for Resource {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_resource().encode(env))?
            .map_put(
                at_logic_ref().encode(env),
                self.logic_ref.rustler_encode(env)?,
            )?
            .map_put(
                at_label_ref().encode(env),
                self.label_ref.rustler_encode(env)?,
            )?
            .map_put(at_quantity().encode(env), self.quantity.encode(env))?
            .map_put(
                at_value_ref().encode(env),
                self.value_ref.rustler_encode(env)?,
            )?
            .map_put(at_is_ephemeral().encode(env), self.is_ephemeral.encode(env))?
            .map_put(
                at_nonce().encode(env),
                self.nonce.to_vec().rustler_encode(env)?,
            )?
            .map_put(
                at_nk_commitment().encode(env),
                self.nk_commitment.rustler_encode(env)?,
            )?
            .map_put(
                at_rand_seed().encode(env),
                self.rand_seed.to_vec().rustler_encode(env)?,
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for Resource {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let logic_ref_term = term.map_get(at_logic_ref().encode(term.get_env()))?;
        let logic_ref = RustlerDecoder::rustler_decode(logic_ref_term)?;

        let label_ref_term = term.map_get(at_label_ref().encode(term.get_env()))?;
        let label_ref = RustlerDecoder::rustler_decode(label_ref_term)?;

        let quantity_term = term.map_get(at_quantity().encode(term.get_env()))?;
        let quantity: u128 = quantity_term.decode()?;

        let value_ref_term = term.map_get(at_value_ref().encode(term.get_env()))?;
        let value_ref = RustlerDecoder::rustler_decode(value_ref_term)?;

        let is_ephemeral_term = term.map_get(at_is_ephemeral().encode(term.get_env()))?;
        let is_ephemeral: bool = is_ephemeral_term.decode()?;

        let nonce_term = term.map_get(at_nonce().encode(term.get_env()))?;
        let nonce: Vec<u8> = RustlerDecoder::rustler_decode(nonce_term)?;

        let nk_commitment_term = term.map_get(at_nk_commitment().encode(term.get_env()))?;
        let nk_commitment: NullifierKeyCommitment =
            RustlerDecoder::rustler_decode(nk_commitment_term)?;

        let rand_seed_term = term.map_get(at_rand_seed().encode(term.get_env()))?;
        let rand_seed: Vec<u8> = RustlerDecoder::rustler_decode(rand_seed_term)?;

        Ok(Resource {
            logic_ref,
            label_ref,
            quantity,
            value_ref,
            is_ephemeral,
            nonce: <[u8; 32]>::try_from(nonce)
                .map_err(|_e| Error::Term(Box::new("invalid_nonce")))?,
            nk_commitment,
            rand_seed: <[u8; 32]>::try_from(rand_seed)
                .map_err(|_e| Error::Term(Box::new("invalid_nonce")))?,
        })
    }
}

impl Encoder for Resource {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode Resource"))
    }
}

impl<'a> Decoder<'a> for Resource {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        Resource::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// DeltaProof

impl RustlerEncoder for DeltaProof {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_delta_proof().encode(env))?
            .map_put(
                at_signature().encode(env),
                self.signature.rustler_encode(env)?,
            )?
            .map_put(at_recid().encode(env), self.recid.rustler_encode(env)?)?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for DeltaProof {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let signature_term = term.map_get(at_signature().encode(term.get_env()))?;
        let signature: Signature = RustlerDecoder::rustler_decode(signature_term)?;

        let recid_term = term.map_get(at_recid().encode(term.get_env()))?;
        let recid: RecoveryId = RustlerDecoder::rustler_decode(recid_term)?;

        Ok(DeltaProof { signature, recid })
    }
}

impl Encoder for DeltaProof {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode DeltaProof"))
    }
}

impl<'a> Decoder<'a> for DeltaProof {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        DeltaProof::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// DeltaWitness

impl RustlerEncoder for DeltaWitness {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_delta_witness().encode(env))?
            .map_put(
                at_signing_key().encode(env),
                self.signing_key.rustler_encode(env)?,
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for DeltaWitness {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let signing_key_term = term.map_get(at_signing_key().encode(term.get_env()))?;
        let signing_key: SigningKey = RustlerDecoder::rustler_decode(signing_key_term)?;

        Ok(DeltaWitness { signing_key })
    }
}

impl Encoder for DeltaWitness {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode DeltaWitness"))
    }
}

impl<'a> Decoder<'a> for DeltaWitness {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        DeltaWitness::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// LogicVerifier

impl RustlerEncoder for LogicVerifier {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_logic_verifier().encode(env))?
            .map_put(at_proof().encode(env), self.proof.rustler_encode(env)?)?
            .map_put(
                at_instance().encode(env),
                self.instance.rustler_encode(env)?,
            )?
            .map_put(
                at_verifying_key().encode(env),
                self.verifying_key.rustler_encode(env)?,
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for LogicVerifier {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let proof_term = term.map_get(at_proof().encode(term.get_env()))?;
        let proof = RustlerDecoder::rustler_decode(proof_term)?;

        let instance_term = term.map_get(at_instance().encode(term.get_env()))?;
        let instance: Vec<u8> = RustlerDecoder::rustler_decode(instance_term)?;

        let verifying_key_term = term.map_get(at_verifying_key().encode(term.get_env()))?;
        let verifying_key = RustlerDecoder::rustler_decode(verifying_key_term)?;

        Ok(LogicVerifier {
            proof,
            instance,
            verifying_key,
        })
    }
}

impl Encoder for LogicVerifier {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.unwrap_or_else(|_e| env.error_tuple("failed to encode LogicVerifier"))
    }
}

impl<'a> Decoder<'a> for LogicVerifier {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        LogicVerifier::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// Transaction

impl RustlerEncoder for Transaction {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        let map = map_new(env)
            .map_put(at_struct().encode(env), at_transaction().encode(env))?
            .map_put(at_actions().encode(env), self.actions.encode(env))?
            .map_put(
                at_delta_proof_field().encode(env),
                self.delta_proof.encode(env),
            )?
            .map_put(
                at_expected_balance().encode(env),
                match &self.expected_balance {
                    Some(balance) => balance.rustler_encode(env)?,
                    None => ().encode(env),
                },
            )?
            .map_put(
                at_aggregation_proof().encode(env),
                match &self.aggregation_proof {
                    Some(proof) => proof.rustler_encode(env)?,
                    None => ().encode(env),
                },
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for Transaction {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let actions_term = term.map_get(at_actions().encode(term.get_env()))?;
        let actions: Vec<Action> = actions_term.decode()?;

        let delta_proof_term = term.map_get(at_delta_proof_field().encode(term.get_env()))?;
        let delta_proof: Delta = delta_proof_term.decode()?;

        let expected_balance_term = term.map_get(at_expected_balance().encode(term.get_env()))?;
        let expected_balance: Option<Vec<u8>> =
            RustlerDecoder::rustler_decode(expected_balance_term)?;

        let aggregation_proof_term = term.map_get(at_aggregation_proof().encode(term.get_env()))?;
        let aggregation_proof: Option<Vec<u8>> =
            RustlerDecoder::rustler_decode(aggregation_proof_term)?;

        Ok(Transaction {
            actions,
            delta_proof,
            expected_balance,
            aggregation_proof,
        })
    }
}

impl Encoder for Transaction {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        self.rustler_encode(env)
            .unwrap_or_else(|_| env.error_tuple("failed to encode Transaction"))
    }
}

impl<'a> Decoder<'a> for Transaction {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        Transaction::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// Delta

impl RustlerEncoder for Delta {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> NifResult<Term<'a>> {
        Ok(self.encode(env))
    }
}

impl<'a> RustlerDecoder<'a> for Delta {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let tuple: (Term, Term) = term.decode()?;
        let tag = tuple.0;
        let value = tuple.1;

        if tag.atom_to_string()? == "proof" {
            let proof: DeltaProof = value.decode()?;
            Ok(Delta::Proof(proof))
        } else if tag.atom_to_string()? == "witness" {
            let witness: DeltaWitness = value.decode()?;
            Ok(Delta::Witness(witness))
        } else {
            Err(Error::BadArg)
        }
    }
}

impl Encoder for Delta {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        match self {
            Delta::Witness(witness) => (at_witness(), witness).encode(env),
            Delta::Proof(proof) => (at_proof(), proof).encode(env),
        }
    }
}

impl<'a> Decoder<'a> for Delta {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        Delta::rustler_decode(term)
    }
}

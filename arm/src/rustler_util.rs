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
use crate::logic_instance::{AppData, ExpirableBlob};
use crate::logic_proof::{LogicVerifier, LogicVerifierInputs};
use crate::merkle_path::MerklePath;
use crate::nullifier_key::{NullifierKey, NullifierKeyCommitment};
use crate::resource::Resource;
use crate::transaction::{Delta, Transaction};
use crate::utils::{bytes_to_words, words_to_bytes};
use bincode;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use k256::AffinePoint;
use rustler::types::atom;
use rustler::types::map::map_new;
use rustler::{atoms, Binary, Decoder, Encoder, NifResult};
use rustler::{Env, Error, OwnedBinary, Term};
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

pub trait RustlerEncoder {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error>;
}

pub trait RustlerDecoder<'a>: Sized + 'a {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self>;
}

impl<T> RustlerEncoder for Option<T>
where
    T: RustlerEncoder,
{
    fn rustler_encode<'c>(&self, env: Env<'c>) -> Result<Term<'c>, Error> {
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let mut erl_bin = OwnedBinary::new(self.len())
            .ok_or("could not create OwnedBinary")
            .expect("could not allocate binary");
        let _ = erl_bin.as_mut_slice().write_all(&self.as_slice());
        Ok(erl_bin.release(env).to_term(env))
    }
}

impl<'a> RustlerDecoder<'a> for Vec<u8> {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let binary: Binary = term.decode().expect("failed to decode binary");
        Ok(binary.as_slice().to_vec())
    }
}

impl RustlerEncoder for Vec<u32> {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let mut erl_bin: OwnedBinary = OwnedBinary::new(self.len() * 4)
            .ok_or("could not create OwnedBinary")
            .expect("could not allocate binary");
        let bytes: &[u8] = words_to_bytes(self.as_slice());
        let _ = erl_bin.as_mut_slice().write_all(bytes);
        Ok(erl_bin.release(env).to_term(env))
    }
}

impl<'a> RustlerDecoder<'a> for Vec<u32> {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let binary: Binary = term.decode().expect("failed to decode binary");
        let bytes: &[u8] = binary.as_slice();
        let words: Vec<u32> = bytes_to_words(bytes);
        Ok(words)
    }
}

impl RustlerEncoder for AffinePoint {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        bincode::serialize(self)
            .expect("failed to encode AffinePoint")
            .rustler_encode(env)
    }
}

impl<'a> RustlerDecoder<'a> for AffinePoint {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let binary: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        let affine_point = bincode::deserialize::<AffinePoint>(binary.as_slice());
        Ok(affine_point.unwrap())
    }
}

impl RustlerEncoder for Signature {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        bincode::serialize(self)
            .expect("failed to encode Signature")
            .rustler_encode(env)
    }
}

impl<'a> RustlerDecoder<'a> for Signature {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let binary: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        let signature = bincode::deserialize::<Signature>(binary.as_slice());
        Ok(signature.unwrap())
    }
}

impl RustlerEncoder for RecoveryId {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let byte: u8 = self.to_byte();
        Ok(byte.encode(env))
    }
}

impl<'a> RustlerDecoder<'a> for RecoveryId {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let byte: u8 = term.decode()?;
        Ok(RecoveryId::from_byte(byte).expect("invalid RecoveryId"))
    }
}

impl RustlerEncoder for SigningKey {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let bytes = self.to_bytes();
        let bytez = bytes.to_vec();
        RustlerEncoder::rustler_encode(&bytez, env)
    }
}

impl<'a> RustlerDecoder<'a> for SigningKey {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let bytez: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        Ok(SigningKey::from_slice(&bytez).expect("invalid SigningKey"))
    }
}

//--------------------------------------------------------------------------------------------------
// ComplianceUnit

impl RustlerEncoder for ComplianceUnit {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let proof: Vec<u8> = RustlerDecoder::rustler_decode(proof_term?)?;
        let instance_term = term.map_get(at_instance().encode(term.get_env()));
        let instance: Vec<u8> = RustlerDecoder::rustler_decode(instance_term?)?;
        Ok(ComplianceUnit { proof, instance })
    }
}

impl Encoder for ComplianceUnit {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode ComplianceUnit")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode ExpirableBlob")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode AppData")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let tag: Vec<u32> = RustlerDecoder::rustler_decode(tag_term)?;
        let verifying_key_term = term.map_get(at_verifying_key().encode(term.get_env()))?;
        let verifying_key: Vec<u32> = RustlerDecoder::rustler_decode(verifying_key_term)?;
        let app_data_term = term.map_get(at_app_data_key().encode(term.get_env()))?;
        let app_data: AppData = app_data_term.decode()?;
        let proof_term = term.map_get(at_proof().encode(term.get_env()))?;
        let proof: Vec<u8> = RustlerDecoder::rustler_decode(proof_term)?;

        Ok(LogicVerifierInputs {
            tag,
            verifying_key,
            app_data,
            proof,
        })
    }
}

impl Encoder for LogicVerifierInputs {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode LogicVerifierInputs")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode Action")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        // encode the leaves separately.
        // each leaf is a vec<u32> and we have to encode those as a binary individually.
        let encoded_vec: Term = self
            .leaves
            .iter()
            .map(|leaf: &Vec<u32>| {
                leaf.rustler_encode(env)
                    .expect("could not encode MerkleTree leaf")
            })
            .collect::<Vec<Term>>()
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
        let leaves_terms =
            Vec::<Term>::decode(leaves_term).expect("failed to decode MerkleTree leaves");

        let leaves: Vec<Vec<u32>> = leaves_terms
            .iter()
            .map(|term| RustlerDecoder::rustler_decode(*term).expect("failed to decode leaf"))
            .collect();

        Ok(MerkleTree { leaves })
    }
}

impl Encoder for MerkleTree {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode MerkleTree")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let encoded_vec: Vec<Term> = self
            .0
            .iter()
            .map(|(hash, is_right)| {
                let hash_term = hash
                    .rustler_encode(env)
                    .expect("could not encode MerklePath hash");
                let is_right_term = is_right.encode(env);
                (hash_term, is_right_term).encode(env)
            })
            .collect();

        Ok(encoded_vec.encode(env))
    }
}

impl<'a> RustlerDecoder<'a> for MerklePath {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let path_terms = Vec::<Term>::decode(term).expect("failed to decode MerklePath list");

        let path: Vec<(Vec<u32>, bool)> = path_terms
            .iter()
            .map(|term| {
                let tuple: (Term, Term) = term.decode().expect("failed to decode MerklePath tuple");
                let hash: Vec<u32> = RustlerDecoder::rustler_decode(tuple.0)
                    .expect("failed to decode MerklePath hash");
                let is_right: bool = tuple
                    .1
                    .decode()
                    .expect("failed to decode MerklePath boolean");
                (hash, is_right)
            })
            .collect();

        Ok(MerklePath(path))
    }
}

impl Encoder for MerklePath {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode MerklePath")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
            .map_put(at_delta_x().encode(env), self.delta_x.rustler_encode(env)?)?
            .map_put(at_delta_y().encode(env), self.delta_y.rustler_encode(env)?)?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for ComplianceInstance {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let consumed_nullifier_term =
            term.map_get(at_consumed_nullifier().encode(term.get_env()))?;
        let consumed_nullifier: Vec<u32> = RustlerDecoder::rustler_decode(consumed_nullifier_term)?;

        let consumed_logic_ref_term =
            term.map_get(at_consumed_logic_ref().encode(term.get_env()))?;
        let consumed_logic_ref: Vec<u32> = RustlerDecoder::rustler_decode(consumed_logic_ref_term)?;

        let consumed_commitment_tree_root_term =
            term.map_get(at_consumed_commitment_tree_root().encode(term.get_env()))?;
        let consumed_commitment_tree_root: Vec<u32> =
            RustlerDecoder::rustler_decode(consumed_commitment_tree_root_term)?;

        let created_commitment_term =
            term.map_get(at_created_commitment().encode(term.get_env()))?;
        let created_commitment: Vec<u32> = RustlerDecoder::rustler_decode(created_commitment_term)?;

        let created_logic_ref_term = term.map_get(at_created_logic_ref().encode(term.get_env()))?;
        let created_logic_ref: Vec<u32> = RustlerDecoder::rustler_decode(created_logic_ref_term)?;

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
            delta_x,
            delta_y,
        })
    }
}

impl Encoder for ComplianceInstance {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode ComplianceInstance")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let ephemeral_root: Vec<u32> = RustlerDecoder::rustler_decode(ephemeral_root_term)?;

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
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode ComplianceWitness")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let inner_bytes = self.inner().to_vec();
        inner_bytes.rustler_encode(env)
    }
}

impl<'a> RustlerDecoder<'a> for NullifierKeyCommitment {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let bytes: Vec<u8> = RustlerDecoder::rustler_decode(term)?;
        Ok(NullifierKeyCommitment::from_bytes(&bytes))
    }
}

impl Encoder for NullifierKeyCommitment {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode NullifierKeyCommitment")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode NullifierKey")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
            .map_put(at_nonce().encode(env), self.nonce.rustler_encode(env)?)?
            .map_put(
                at_nk_commitment().encode(env),
                self.nk_commitment.rustler_encode(env)?,
            )?
            .map_put(
                at_rand_seed().encode(env),
                self.rand_seed.rustler_encode(env)?,
            )?;

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for Resource {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let logic_ref_term = term.map_get(at_logic_ref().encode(term.get_env()))?;
        let logic_ref: Vec<u8> = RustlerDecoder::rustler_decode(logic_ref_term)?;

        let label_ref_term = term.map_get(at_label_ref().encode(term.get_env()))?;
        let label_ref: Vec<u8> = RustlerDecoder::rustler_decode(label_ref_term)?;

        let quantity_term = term.map_get(at_quantity().encode(term.get_env()))?;
        let quantity: u128 = quantity_term.decode()?;

        let value_ref_term = term.map_get(at_value_ref().encode(term.get_env()))?;
        let value_ref: Vec<u8> = RustlerDecoder::rustler_decode(value_ref_term)?;

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
            nonce,
            nk_commitment,
            rand_seed,
        })
    }
}

impl Encoder for Resource {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode Resource")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode DeltaProof")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode DeltaWitness")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let proof: Vec<u8> = RustlerDecoder::rustler_decode(proof_term)?;

        let instance_term = term.map_get(at_instance().encode(term.get_env()))?;
        let instance: Vec<u8> = RustlerDecoder::rustler_decode(instance_term)?;

        let verifying_key_term = term.map_get(at_verifying_key().encode(term.get_env()))?;
        let verifying_key: Vec<u32> = RustlerDecoder::rustler_decode(verifying_key_term)?;

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
        encoded.expect("failed to encode LogicVerifier")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
        let expected_balance: Option<Vec<u8>> = match expected_balance_term.decode::<()>() {
            Ok(_) => None,
            Err(_) => Some(RustlerDecoder::rustler_decode(expected_balance_term)?),
        };

        Ok(Transaction {
            actions,
            delta_proof,
            expected_balance,
        })
    }
}

impl Encoder for Transaction {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode Transaction")
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
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
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
            Err(rustler::Error::BadArg)
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

defmodule ArmRisc0.Verifier do
  # `crate: :arm_nif` would default to `native/arm_nif/` relative to the mix
  # project root. The crate lives at the repo root here, so point `path:` at it.
  use Rustler,
    otp_app: :arm_risc0,
    crate: :arm_nif,
    path: "arm_nif"

  @moduledoc """
  NIF bindings for verifying arm-risc0 resource machine transactions.

  All functions take a bincode-encoded `anoma_rm_risc0::transaction::Transaction`
  as a binary.
  """

  @typedoc "Result type for NIF functions that can return errors"
  @type nif_result(t) :: t | {:error, term()}

  @typedoc "A payload blob: its raw u32 words and deletion criterion."
  @type blob :: {[non_neg_integer()], non_neg_integer()}

  @typedoc "The four payload categories: {resource, discovery, external, application}."
  @type app_data_blobs :: {[blob()], [blob()], [blob()], [blob()]}

  @doc """
  Verify a bincode-encoded Transaction
  """
  @spec verify_transaction(binary()) :: nif_result(boolean())
  def verify_transaction(_tx_bytes), do: error()

  @doc """
  Decode + verify a transaction in one pass and return its effects needed for
  global checks and storage
  """
  @spec verify_and_extract(binary()) ::
          {[{<<_::256>>, app_data_blobs()}], [{<<_::256>>, app_data_blobs()}], [<<_::256>>]}
          | {:error, term()}
  def verify_and_extract(_tx_bytes), do: error()

  @doc "All nullifiers (32-byte binaries) in the transaction, in transaction order."
  @spec transaction_nullifiers(binary()) :: nif_result(list(<<_::256>>))
  def transaction_nullifiers(_tx_bytes), do: error()

  @doc "All commitments (32-byte binaries) in the transaction, in transaction order."
  @spec transaction_commitments(binary()) :: nif_result(list(<<_::256>>))
  def transaction_commitments(_tx_bytes), do: error()

  @doc """
  The set of consumed-resource roots in the transaction
  """
  @spec transaction_roots(binary()) :: nif_result(list(<<_::256>>))
  def transaction_roots(_tx_bytes), do: error()

  defp error, do: :erlang.nif_error(:nif_not_loaded)
end

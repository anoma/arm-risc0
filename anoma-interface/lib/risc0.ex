defmodule Risc0 do
  @spec prove(list(byte()), list(byte())) ::
          list(byte()) | {:error, term()}
  defdelegate prove(env_bytes, elf),
    to: Risc0.Risc0Prover,
    as: :prove

  @spec verify(list(byte()), list(byte())) ::
          boolean() | {:error, term()}
  defdelegate verify(receipt_bytes, elf),
    to: Risc0.Risc0Prover,
    as: :verify


  @spec generate_resource(
    list(byte()),
    list(byte()),
    list(byte()),
    list(byte()),
    list(boolean()),
    list(byte()),
    list(byte()),
    list(byte()))  ::
    list(byte()) | {:error, term()}
  defdelegate generate_resource(
    label,
    nonce,
    quantity,
    value,
    eph,
    nsk,
    image_id,
    rseed),
    to: Risc0.Risc0Prover,
    as: :generate_resource

    @spec generate_compliance_circuit(
      list(byte()),
      list(byte()),
      list(byte()),
      list(byte()),
      list(byte())
    ) :: list(byte()) | {:error, term()}
    defdelegate generate_compliance_circuit(
      input_resource,
      output_resource,
      rcv,
      merkle_path,
      nsk
    ), to: Risc0.Risc0Prover, as: :generate_compliance_circuit

    @spec random_32() :: list(byte()) | {:error, term()}
    defdelegate random_32(), to: Risc0.Risc0Prover, as: :random_32

    @spec generate_merkle_path_32() :: list(byte()) | {:error, term()}
    defdelegate generate_merkle_path_32(), to: Risc0.Risc0Prover, as: :generate_merkle_path_32

    @spec generate_nsk() :: list(byte()) | {:error, term()}
    defdelegate generate_nsk(), to: Risc0.Risc0Prover, as: :generate_nsk
    @spec encrypt(
      list(byte()),
      list(byte()),
      list(byte()),
      list(byte())
    ) :: list(byte()) | {:error, term()}
    defdelegate encrypt(
      message,
      pk_bytes,
      sk_bytes,
      nonce_bytes
    ), to: Risc0.Risc0Prover, as: :encrypt

    @spec decrypt(
      list(byte()),
      list(byte()),
      list(byte()),
      list(byte())
    ) :: list(byte()) | {:error, term()}
    defdelegate decrypt(
      cipher,
      pk_bytes,
      sk_bytes,
      nonce_bytes
    ), to: Risc0.Risc0Prover, as: :decrypt

end

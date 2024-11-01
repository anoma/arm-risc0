defmodule Risc0ComplianceTest do
  use ExUnit.Case

  # doctest Risc0.Risc0Prover
  # doctest Risc0.Risc0VM
  @compliance_guest_elf File.read!("../compliance-circuit/target/riscv-guest/riscv32im-risc0-zkvm-elf/release/compliance_guest")
  @compliance_guest_id [3158653199, 3603290836, 2377543753, 943534379, 707928066, 1099487722, 3703862186, 753768222]

  @tag timeout: :infinity
  test "compliance_circuit" do
    compliance_guest_elf = @compliance_guest_elf |> :binary.bin_to_list()
    compliance_guest_id = @compliance_guest_id

    label = Risc0.random_32()
    nonce_1 = Risc0.random_32()
    nonce_2 = Risc0.random_32()
    quantity = Risc0.random_32()
    value = Risc0.random_32()
    eph = false # :binary.encode_unsigned(0)# |> :binary.bin_to_list()
    nsk = Risc0.generate_nsk()
    rcv = Risc0.random_32()
    rseed_1 = Risc0.random_32()
    rseed_2 = Risc0.random_32()
    image_id = Risc0.random_32()
    merkle_path = Risc0.generate_merkle_path_32()

    input_resource = Risc0.generate_resource(
      label,
      nonce_1,
      quantity,
      value,
      eph,
      nsk,
      image_id,
      rseed_1
    )

    output_resource = Risc0.generate_resource(
      label,
      nonce_2,
      quantity,
      value,
      eph,
      nsk,
      image_id,
      rseed_2
    )

    compliance_circuit = Risc0.generate_compliance_circuit(
      input_resource,
      output_resource,
      rcv,
      merkle_path,
      nsk
    )

    # Prove and verify
    receipt = Risc0.prove(compliance_circuit, compliance_guest_elf)
    verify = Risc0.verify(receipt, compliance_guest_id)
    assert true == verify
  end
end

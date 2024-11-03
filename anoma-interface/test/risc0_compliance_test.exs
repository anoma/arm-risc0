defmodule Risc0ComplianceTest do
  use ExUnit.Case

  @compliance_guest_elf File.read!("../compliance-circuit/target/riscv-guest/riscv32im-risc0-zkvm-elf/release/compliance_guest")
  # Found in ../compliance-circuit/target/debug/build/methods-38f440f6c1f89eed/out/methods.rs
  @compliance_guest_id [628739029, 195810266, 3068426337, 784798236, 919101207, 745839261, 1195377994, 400294044]

  @tag timeout: :infinity
  test "compliance_circuit" do
    compliance_guest_elf = @compliance_guest_elf |> :binary.bin_to_list()
    compliance_guest_id = @compliance_guest_id

    label = Risc0.random_32()
    nonce_1 = Risc0.random_32()
    nonce_2 = Risc0.random_32()
    quantity = Risc0.random_32()
    value = Risc0.random_32()
    eph = false
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

In the context of Elixir/Erlang, NIF stands for **Native Implemented Function**. NIFs are a way to implement Erlang/Elixir functions in native code (typically C or Rust) for performance-critical operations or to interface with system libraries.

Rustler is a tool for safely writing NIFs in Rust. The structure of this repo is due to the way the Rustler library works.
```
risc0/
├── lib/
│   ├── risc0.ex
│   └── risc0/
│       └── risc0.ex
└── native/
    └── risc0_prover/
        ├── Cargo.toml
        └── src/
            ├── Cargo.toml
            └── src/
                └── lib.rs
```



# NIF for Elixir.Risc0

## To build the NIF module:

- Your NIF will now build along with your project.

## To load the NIF:

```elixir
defmodule Risc0.Risc0Prover do
  use Rustler, otp_app: :risc0, crate: :risc0_prover

  # When your NIF is loaded, it will override this function.
  def prove(_arg1, _arg2), do: :erlang.nif_error(:nif_not_loaded)
  def verify(_arg1, _arg2), do: :erlang.nif_error(:nif_not_loaded)
end
```

## To test the NIF:

- You must have the risc0-zkvm toolchain installed.
- Compile the compliance circuit with `cargo build` in the `compliance-circuit` directory. This is necessary to generate the guest ELF and ID files.
- If you are on macOS, you must have XCode installed. To build with the `prove` flag on macOS, you'll need to have the full version of XCode installed, which includes the 'metal' compiler. We need the `prove` feature flag to have the proving happen in the same process. Otherwise, with `default` feature flags, the prover will try to launch a `r0vm` server process to perform the actual proving. If you're calling this from some other environment, it will throw a "No child processses" error.
- You can run the tests with `mix test`.

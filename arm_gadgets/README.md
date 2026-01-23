# Anoma Resource Machine Gadgets

Cryptographic gadgets and utilities for building resource logic circuits in the Anoma Resource Machine using RISC0 zkVM.

## Overview

The `anoma-rm-risc0-gadgets` crate provides a collection of reusable components for implementing resource logic in the Anoma protocol. These gadgets include cryptographic primitives commonly needed in zero-knowledge proofs, such as signing, encryption, and EVM interoperability.

## Features

### Authority & Signing

The `authority` module provides ECDSA signature generation and verification over the secp256k1 elliptic curve:

- **`AuthoritySigningKey`**: Generate and use signing keys for creating digital signatures
- **`AuthorityVerifyingKey`**: Verify signatures using public keys
- **`AuthoritySignature`**: Represent and work with ECDSA signatures
- Domain separator support for protocol versioning

Example use case: Authenticate resource operations with cryptographic signatures.

### Encryption

The `encryption` module provides symmetric encryption and decryption utilities:

- **`SecretKey`**: Manage secret keys with automatic zeroization for security
- **`PublicKey`**: Derive and use public keys from secret keys
- **`Ciphertext`**: Represent encrypted data
- **`EncryptedValue`**: Combined structure of ciphertext and associated public key
- AES-256-GCM encryption with authentication
- Elliptic curve Diffie-Hellman (ECDH) key derivation

Example use case: Encrypt sensitive resource data and share with authorized parties using their public keys.

### EVM Interoperability

The `evm` module enables compatibility with Ethereum Virtual Machine (EVM) systems:

- **`Resource` struct**: EVM-compatible representation of ARM resources with ABI encoding/decoding
- **`ForwarderCalldata`**: A data structure containing the input data to be forwarded to the untrusted forwarder contract and the anticipated output data
- Conversion between ARM resources and EVM-compatible formats
- Solidity contract interaction support

Example use case: Bridge ARM resources with EVM-based applications and smart contracts.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
anoma-rm-risc0-gadgets = "1.0"
```

## License

Licensed under the Apache License 2.0. See [LICENSE](../LICENSE) for details.

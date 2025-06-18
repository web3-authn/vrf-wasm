# VRF Contract Verification Library

A minimal, optimized VRF proof verification library specifically designed for smart contracts on WASM-based platforms like NEAR, CosmWasm, and others.

## Features

- ✅ **Minimal Dependencies**: Only essential crypto libraries, no RNG or signing
- ✅ **No-std Compatible**: Works in constrained smart contract environments
- ✅ **Multi-Platform**: NEAR, CosmWasm, and generic WASM support
- ✅ **Sui VRF Compatible**: Implements the same VRF suite as Sui blockchain
- ✅ **Size Optimized**: ~10KB compiled size vs 100KB+ for full libraries
- ✅ **Battle Tested**: Uses proven verification logic from FastCrypto

## Quick Start

### Basic Usage

```rust
use vrf_contract_verify::{VrfProof, VrfPublicKey};

// Verify a VRF proof
let public_key = VrfPublicKey::from_bytes(pk_bytes);
let proof = VrfProof::from_raw_bytes(&proof_bytes)?;

// Basic verification
proof.verify(&input, &public_key)?;

// Verify with expected output
let output = proof.to_output()?;
proof.verify_output(&input, &public_key, &output)?;
```

### NEAR Smart Contract

```toml
[dependencies]
vrf-contract-verify = { version = "0.1", features = ["near"] }
```

```rust
use vrf_contract_verify::near::VrfVerifier;

#[near_bindgen]
impl MyContract {
    pub fn verify_randomness(&self, proof: Vec<u8>, pk: Vec<u8>, seed: Vec<u8>) -> bool {
        let verifier = VrfVerifier::new();
        verifier.verify_vrf(proof, pk, seed)
    }
}
```

### CosmWasm Smart Contract

```toml
[dependencies]
vrf-contract-verify = { version = "0.1", features = ["cosmwasm"] }
```

```rust
use vrf_contract_verify::cosmwasm::verify_vrf_proof;

pub fn verify_randomness(proof: &[u8], pk: &[u8], input: &[u8]) -> bool {
    verify_vrf_proof(proof, pk, input).unwrap_or(false)
}
```

## API Reference

### Core Types

#### `VrfPublicKey`
32-byte compressed Ristretto point representing the VRF public key.

```rust
let pk = VrfPublicKey::from_bytes(bytes);
assert!(pk.is_valid());
```

#### `VrfProof`
VRF proof containing gamma point, challenge, and scalar response.

```rust
let proof = VrfProof::new(gamma, challenge, scalar);
// Or from serialized bytes
let proof = VrfProof::from_raw_bytes(&bytes)?;
```

#### `VrfOutput`
64-byte VRF output hash.

```rust
let output: VrfOutput = proof.to_output()?;
```

### Verification Methods

#### `proof.verify(input, public_key)`
Basic VRF proof verification.

#### `proof.verify_output(input, public_key, expected_output)`
Verify proof and check the output matches expected value.

#### `proof.to_output()`
Extract the VRF output hash from a valid proof.

## Build Configuration

### For Smart Contracts
```toml
# Minimal build
vrf-contract-verify = { version = "0.1", default-features = false }

# With NEAR support
vrf-contract-verify = { version = "0.1", features = ["near"] }

# With CosmWasm support
vrf-contract-verify = { version = "0.1", features = ["cosmwasm"] }
```

### WASM Build
```bash
# Build for WASM targets
cargo build --target wasm32-unknown-unknown --release --no-default-features

# With contract features
cargo build --target wasm32-unknown-unknown --release --features near
```

## Size Optimization

This library is optimized for minimal size in smart contracts:

- **Dependencies**: Only curve25519-dalek-ng + sha2 + minimal serde
- **No RNG**: No random number generation dependencies
- **No Signing**: Only verification logic included
- **No Precomputed Tables**: Avoids static initialization issues
- **Manual Scalar Mul**: Uses simple fold instead of optimized multiscalar

**Result**: ~10KB compiled WASM vs 100KB+ for full VRF libraries.

## Compatibility

### VRF Suite
Compatible with Sui VRF implementation:
- Suite string: `sui_vrf`
- Curve: Ristretto255
- Hash: SHA-512
- Challenge length: 16 bytes
- Output length: 64 bytes

### Smart Contract Platforms
- ✅ NEAR Protocol
- ✅ CosmWasm (Cosmos SDK)
- ✅ Generic WASM contracts
- ✅ Substrate/Polkadot (with modifications)

## Security Notes

- This library only performs **verification** - never generate keys or proofs in contracts
- Use hardware security modules or secure enclaves for key generation
- Verify proofs were generated with proper randomness
- Consider replay attack protection in your contract logic

## Example: NEAR VRF Oracle

```rust
use near_sdk::{near_bindgen, PanicOnDefault};
use vrf_contract_verify::near::VrfVerifier;

#[near_bindgen]
#[derive(PanicOnDefault)]
pub struct VrfOracle {
    verifier: VrfVerifier,
    authorized_keys: Vec<[u8; 32]>,
}

#[near_bindgen]
impl VrfOracle {
    #[init]
    pub fn new(authorized_keys: Vec<Vec<u8>>) -> Self {
        Self {
            verifier: VrfVerifier::new(),
            authorized_keys: authorized_keys.into_iter()
                .map(|k| k.try_into().expect("Invalid key length"))
                .collect(),
        }
    }

    pub fn submit_randomness(
        &mut self,
        proof: Vec<u8>,
        public_key: Vec<u8>,
        round: u64,
    ) -> bool {
        // Check if key is authorized
        let pk_array: [u8; 32] = public_key.clone().try_into()
            .expect("Invalid public key length");

        if !self.authorized_keys.contains(&pk_array) {
            return false;
        }

        // Verify the VRF proof
        let input = round.to_le_bytes();
        self.verifier.verify_vrf(proof, public_key, input.to_vec())
    }
}
```

## License

Apache-2.0
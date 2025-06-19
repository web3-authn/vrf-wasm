# VRF Verification Library for WASM contracts

A minimal, optimized VRF proof verification library specifically designed for smart contracts on WASM-based platforms like NEAR, CosmWasm, and others.

## Features

- **Minimal Dependencies**: Only essential crypto libraries, no RNG or signing
- **No-std Compatible**: Works in constrained smart contract environments
- **Multi-Platform**: NEAR, CosmWasm, and generic WASM support
- **Size Optimized**: ~10KB compiled size vs 100KB+ for full libraries
- **Conditional Compilation**: Only include platform-specific code when needed
- **Battle Tested**: Uses proven verification logic from FastCrypto

## Quick Start

### Basic Usage (Generic WASM)

```rust
use vrf_contract_verifier::near_vrf_verifier::{verify_vrf, VerificationError};

// Verify a VRF proof (80 bytes: gamma(32) + challenge(16) + scalar(32))
let result = verify_vrf(proof_bytes, public_key_bytes, input_bytes);
match result {
    Ok(vrf_output) => {
        // VRF proof is valid, use the 64-byte output
        println!("VRF output: {:?}", vrf_output);
    }
    Err(VerificationError::InvalidProof) => {
        // Invalid proof
    }
    Err(e) => {
        // Other verification errors
    }
}
```

### NEAR Smart Contract

```toml
[dependencies]
vrf-contract-verifier = { version = "0.4.3", features = ["near"] }
```

```rust
use vrf_contract_verifier::near_vrf_verifier::{verify_vrf_bool, verify_vrf};

#[near_bindgen]
impl MyContract {
    // Simple boolean verification
    pub fn verify_randomness(&self, proof: Vec<u8>, pk: Vec<u8>, seed: Vec<u8>) -> bool {
        verify_vrf_bool(proof, pk, seed)
    }

    // Full verification with VRF output
    pub fn verify_and_get_output(&self, proof: Vec<u8>, pk: Vec<u8>, seed: Vec<u8>) -> Option<Vec<u8>> {
        match verify_vrf(proof, pk, seed) {
            Ok(output) => Some(output.to_vec()),
            Err(_) => None,
        }
    }
}
```

### Generic WASM (without platform-specific features)

```toml
[dependencies]
vrf-contract-verifier = { version = "0.4.3", default-features = false }
```

## API Reference

### Core Verification Functions

All verification functions are in the `near_vrf_verifier` module:

#### `verify_vrf(proof_bytes, public_key_bytes, input) -> Result<VrfOutput, VerificationError>`
Complete VRF verification returning the 64-byte VRF output on success.

#### `verify_vrf_fixed(proof_array, public_key_array, input) -> Result<VrfOutput, VerificationError>`
Type-safe version using fixed-size arrays instead of Vec.

#### `verify_vrf_bool(proof_bytes, public_key_bytes, input) -> bool`
Simple boolean verification for contract usage.

### Error Types

```rust
pub enum VerificationError {
    InvalidProof,
    InvalidInput,
    InvalidPublicKey,
    InvalidProofLength,
    DecompressionFailed,
    InvalidScalar,
    InvalidGamma,
    ZeroPublicKey,
    ExpandMessageXmdFailed,
}
```

## Build Configuration

### Features

| Feature | Description | Dependencies Added |
|---------|-------------|-------------------|
| `default` | No platform features | Base crypto only |
| `near` | NEAR smart contract support | `near-sdk`, `bincode` |
| `cosmwasm` | CosmWasm support | `bincode` |

### Conditional Compilation Examples

```bash
# Build without any platform features (smallest)
cargo build --target wasm32-unknown-unknown --no-default-features --release

# Build for NEAR smart contracts
cargo build --target wasm32-unknown-unknown --features near --no-default-features --release

# Build for CosmWasm
cargo build --target wasm32-unknown-unknown --features cosmwasm --no-default-features --release

# Test all configurations
cargo test                                    # Basic features
cargo test --features near                   # With NEAR features
cargo test --features cosmwasm               # With CosmWasm features
```

### Platform-Specific Build Optimization

The crate uses conditional compilation to minimize dependencies:

```rust
// NEAR-specific serialization only when needed
#[cfg_attr(feature = "near", near_sdk::near(serializers = [borsh, json]))]
pub struct VrfProof { ... }

// Platform-specific dependencies only when features are enabled
#[cfg(feature = "near")]
use near_sdk;

#[cfg(feature = "cosmwasm")]
use cosmwasm_std;
```

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

## Security Notes

- This library only performs **verification** - does not generate keys or proofs in contracts
- Verify proofs were generated with proper randomness
- Consider replay attack protection in contract logic

## Example: NEAR VRF Oracle

```rust
use near_sdk::{near_bindgen, PanicOnDefault};
use vrf_contract_verifier::near::VrfVerifier;

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
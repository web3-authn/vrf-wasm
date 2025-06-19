# VRF Verification Library for WASM contracts

A minimal, optimized VRF proof verification library specifically designed for smart contracts on WASM-based platforms like NEAR, CosmWasm, and others.

## Features

- **Minimal Dependencies**: Only essential crypto libraries, no RNG or signing
- **No-std Compatible**: Works in constrained smart contract environments
- **Multi-Platform**: NEAR, CosmWasm, and generic WASM support
- **Size Optimized**: ~10KB compiled size vs 100KB+ for full libraries
- **Conditional Compilation**: Only include platform-specific code when needed
- **Battle Tested**: Uses proven verification logic from FastCrypto

## Installation

### Generic WASM Contracts (Default)

```toml
[dependencies]
vrf-contract-verifier = "0.7"
```

### NEAR Smart Contracts

For NEAR smart contracts with enhanced features:

```toml
[dependencies]
vrf-contract-verifier = { version = "0.7", features = ["near"] }
```

### Using with VRF-WASM for Proof Generation

When using both libraries together, ensure consistent feature configuration:

```toml
[dependencies]
# For proof generation (NEAR contracts)
vrf-wasm = { version = "0.7", default-features = false, features = ["near"] }
# For proof verification (NEAR contracts)
vrf-contract-verifier = { version = "0.7", features = ["near"] }
```

## Quick Start

### Basic Usage (Generic WASM)

```rust
use vrf_contract_verifier::{verify_vrf, VerificationError};

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

```rust
use vrf_contract_verifier::{verify_vrf_bool, verify_vrf};

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

## API Reference

### Core Verification Functions

#### `verify_vrf(proof_bytes, public_key_bytes, input) -> Result<VrfOutput, VerificationError>`
Complete VRF verification returning the 64-byte VRF output on success.

#### `verify_vrf_fixed(proof_array, public_key_array, input) -> Result<VrfOutput, VerificationError>`
Type-safe version using fixed-size arrays instead of Vec.

#### `verify_vrf_bool(proof_bytes, public_key_bytes, input) -> bool`
Simple boolean verification for contract usage.


### Build Examples

```bash
# Build without any platform features (smallest)
cargo build --target wasm32-unknown-unknown --release

# Build for NEAR contracts specifically
cargo build --target wasm32-unknown-unknown --features near --release

# Test all configurations
cargo test                                   # Basic features
cargo test --features near                   # With NEAR features
```

### Important Notes

- **Feature Compatibility**: When using both `vrf-wasm` and `vrf-contract-verifier` in the same project, ensure consistent feature flags
- **NEAR Runtime**: The `near` feature enables NEAR-specific optimizations but requires NEAR runtime for execution
- **Cross-Verification**: Both libraries use identical cryptographic implementations for compatibility

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


## License

Apache-2.0
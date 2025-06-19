# VRF-WASM

A pure-Rust VRF (Verifiable Random Function) implementation optimized for WASM environments, including web browsers and smart contracts.

## Project Structure

This repository contains multiple crates for different use cases:

### 🌐 [`vrf-wasm/`](./vrf-wasm/) - VRF for WASM environments (e.g browser workers)
Complete VRF implementation with key generation, signing, and verification:
- **Key Generation**: Secure VRF keypair creation
- **Proof Generation**: Create VRF proofs with randomness
- **Verification**: Verify VRF proofs and outputs
- **WASM Compatible**: Works in browsers and Node.js
- **Size**: 175KB optimized

**Use for**: Client-side applications, oracles, services that need full VRF functionality

### 🔗 [`vrf-wasm-js/`](./vrf-wasm-js/) - JavaScript Bindings
Browser and Node.js bindings for the full VRF library:
- **TypeScript Support**: Full type definitions
- **Easy Integration**: Simple npm package
- **Modern APIs**: Promise-based async functions

### 📋 [`vrf-contract-verifier/`](./vrf-contract-verifier/) - NEAR Contract VRF Proof Verifier
**NEW**: Minimal verification-only library optimized for smart contracts:
- **Ultra-Minimal**: Only verification logic (86 bytes optimized)
- **No-std Compatible**: Works in constrained environments
- **Multi-Platform**: NEAR and generic WASM
- **Battle Tested**: Uses proven verification logic
- **Fast**: Optimized for contract gas costs

**Use for**: Smart contracts that only need to verify VRF proofs


## Feature Comparison

| Feature | vrf-wasm | vrf-wasm-js | vrf-contract-verifier |
|---------|----------|-------------|---------------------|
| Key Generation | ✅ | ✅ | ❌ |
| Proof Creation | ✅ | ✅ | ❌ |
| Proof Verification | ✅ | ✅ | ✅ |
| Browser Support | ✅ | ✅ | ❌ |
| Node.js Support | ✅ | ✅ | ❌ |
| NEAR Contracts | ⚠️ | ❌ | ✅ |
| Generic WASM | ⚠️ | ❌ | ✅ |
| Compiled Size | 175 KB | 267 KB | **86 bytes** |
| Dependencies | Many | Many | Minimal |

⚠️ = Possible but not optimized

## Binary Size Comparison

Detailed comparison of compiled WASM binary sizes (optimized release builds with `opt-level="s"`):

| Library | Binary Size | Size Ratio | Use Case |
|---------|-------------|------------|----------|
| **vrf-contract-verifier** | **86 bytes** | **1x** (baseline) | ✅ Proof verification only |
| **vrf-wasm** | **175 KB** | **2,090x larger** | ✅ Full VRF operations |
| **vrf-wasm-js** | **267 KB** | **3,183x larger** | ✅ Browser-optimized |

### Why Such Different Sizes?

The **2,090x size difference** between `vrf-contract-verifier` and `vrf-wasm` comes from:

1. **Functionality Scope**:
   - `vrf-contract-verifier`: Only verification logic
   - `vrf-wasm`: Complete VRF implementation (keygen, signing, verification)

2. **Dependencies**:
   - `vrf-contract-verifier`: Minimal crypto primitives only
   - `vrf-wasm`: RNG, serialization, encoding, multiple hash functions

3. **Target Environment**:
   - `vrf-contract-verifier`: Optimized for smart contracts where every byte counts
   - `vrf-wasm`: General-purpose WASM environments

### Debug vs Release Optimization

| Library | Debug Size | Optimized Release | Optimization Factor |
|---------|------------|------------------|-------------------|
| vrf-wasm | 8.4 MB | 175 KB | 49x reduction |
| vrf-wasm-js | 10.1 MB | 267 KB | 39x reduction |
| vrf-contract-verifier | N/A | 86 bytes | Ultra-minimal |

## Smart Contract Platforms

### Supported Platforms (vrf-contract-verify)
- ✅ **NEAR Protocol**: Native integration with near-sdk
- ✅ **CosmWasm**: Cosmos SDK smart contracts
- ✅ **Generic WASM**: Any WASM-based contract platform
- 🔄 **Substrate/Polkadot**: With minimal modifications


## WASM Compatibility

Both `vrf-wasm` and `vrf-contract-verifier` crates are designed for WASM environments:
- **No std**: Compatible with no-std environments
- **No global statics**: Avoids initialization issues
- **Pure Rust**: No external dependencies on system libraries
- **Optimized builds**: Minimal code size with `--release` builds

## VRF Specification

Implements ECVRF with:
- **Curve**: Ristretto255 (prime-order group over Curve25519)
- **Hash Function**: SHA-512
- **Suite String**: `sui_vrf`
- **Output Length**: 64 bytes
- **Challenge Length**: 16 bytes

## Examples

### Smart Contract Oracle
```rust
// NEAR contract that verifies VRF proofs from authorized oracles
use vrf_contract_verifier::near::VrfVerifier;

#[near_bindgen]
impl RandomnessOracle {
    pub fn submit_random(&mut self, proof: Vec<u8>, round: u64) -> bool {
        let input = round.to_le_bytes();
        self.verifier.verify_vrf(proof, self.oracle_pubkey.clone(), input.to_vec())
        // ...
    }
}
```

### Client-side Random Generation
```javascript
// Generate verifiable randomness in browser
import { VRFKeyPairJS } from 'vrf-wasm-js';

const keypair = new VRFKeyPairJS();
const seed = crypto.getRandomValues(new Uint8Array(32));
const { hash, proof } = keypair.output(seed);

// hash can be used as randomness
// proof can be sent to contracts for verification
``

## License

Apache-2.0 - See [LICENSE](LICENSE) for details.

# VRF-WASM

A pure-Rust VRF (Verifiable Random Function) implementation optimized for WASM environments, including web browsers and smart contracts.

## Project Structure

This repository contains multiple crates for different use cases:

### [`vrf-wasm/`](./vrf-wasm/) - VRF for WASM environments (e.g browser workers)
Complete VRF implementation with key generation, signing, and verification:
- **Key Generation**: Secure VRF keypair creation
- **Proof Generation**: Create VRF proofs with randomness
- **Verification**: Verify VRF proofs and outputs
- **WASM Compatible**: Works in browsers and Node.js
- **Size**: 175KB optimized

**Use for**: Client-side applications, oracles, services that need full VRF functionality

### [`vrf-wasm-js/`](./vrf-wasm-js/) - JavaScript Bindings
Browser and Node.js bindings for the full VRF library:

### [`vrf-contract-verifier/`](./vrf-contract-verifier/) - NEAR Contract VRF Proof Verifier
Minimal verification-only library optimized for smart contracts:

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
| Dependencies | Many | Many | Minimal |

⚠️ = not optimized

## Binary Size Comparison

Compiled WASM binary sizes (optimized release builds with `opt-level="s"`) as follows:

| Library | Binary Size | Size Ratio | Use Case |
|---------|-------------|------------|----------|
| **vrf-contract-verifier** | **86 bytes** | **1x** (baseline) | Proof verification only |
| **vrf-wasm** | **175 KB** | **2,090x larger** | Full VRF operations |
| **vrf-wasm-js** | **267 KB** | **3,183x larger** | Browser-optimized |

The size difference between `vrf-contract-verifier` and `vrf-wasm` comes from:

1. **Scope**:
   - `vrf-contract-verifier`: Only verification logic
   - `vrf-wasm`: Complete VRF implementation (keygen, signing, verification)

2. **Dependencies**:
   - `vrf-contract-verifier`: Minimal crypto primitives only
   - `vrf-wasm`: RNG, serialization, encoding, multiple hash functions

3. **Target Environment**:
   - `vrf-contract-verifier`: Optimized for smart contracts
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
- ✅ **Generic WASM**: Any WASM-based contract platform such as Sui but this needs testing.


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

## License

Apache-2.0 - See [LICENSE](LICENSE) for details.

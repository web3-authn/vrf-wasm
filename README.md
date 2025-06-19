# VRF-WASM

A pure-Rust VRF (Verifiable Random Function) implementation optimized for WASM environments, including web browsers and smart contracts.

## Project Structure

This repository contains multiple crates for different use cases:

### 🌐 [`vrf-wasm/`](./vrf-wasm/) - Full VRF Library
Complete VRF implementation with key generation, signing, and verification:
- **Key Generation**: Secure VRF keypair creation
- **Proof Generation**: Create VRF proofs with randomness
- **Verification**: Verify VRF proofs and outputs
- **WASM Compatible**: Works in browsers and Node.js
- **Size**: ~100KB compiled

**Use for**: Client-side applications, oracles, services that need full VRF functionality

### 🔗 [`vrf-wasm-js/`](./vrf-wasm-js/) - JavaScript Bindings
Browser and Node.js bindings for the full VRF library:
- **TypeScript Support**: Full type definitions
- **Easy Integration**: Simple npm package
- **Modern APIs**: Promise-based async functions

### 📋 [`vrf-contract-verify/`](./vrf-contract-verify/) - Contract Verification Only
**NEW**: Minimal verification-only library optimized for smart contracts:
- **Minimal**: Only verification logic (~10KB compiled)
- **No-std Compatible**: Works in constrained environments
- **Multi-Platform**: NEAR, CosmWasm, generic WASM
- **Battle Tested**: Uses proven verification logic
- **Fast**: Optimized for contract gas costs

**Use for**: Smart contracts that only need to verify VRF proofs

## Quick Start

### For Smart Contracts (Verification Only)
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

### For Web Applications (Full VRF)
```bash
npm install vrf-wasm-js
```

```javascript
import { VRFKeyPairJS } from 'vrf-wasm-js';

const keypair = new VRFKeyPairJS();
const proof = keypair.prove(new TextEncoder().encode("random seed"));
const output = keypair.output(new TextEncoder().encode("random seed"));
```

### For Rust Applications
```toml
[dependencies]
vrf-wasm = "0.3"
```

```rust
use vrf_wasm::{ECVRFKeyPair, VRFKeyPair};

let keypair = ECVRFKeyPair::generate(&mut rng);
let proof = keypair.prove(b"input data");
```

## Feature Comparison

| Feature | vrf-wasm | vrf-wasm-js | vrf-contract-verify |
|---------|----------|-------------|-------------------|
| Key Generation | ✅ | ✅ | ❌ |
| Proof Creation | ✅ | ✅ | ❌ |
| Proof Verification | ✅ | ✅ | ✅ |
| Browser Support | ✅ | ✅ | ❌ |
| Node.js Support | ✅ | ✅ | ❌ |
| NEAR Contracts | ⚠️ | ❌ | ✅ |
| CosmWasm Contracts | ⚠️ | ❌ | ✅ |
| Compiled Size | ~100KB | ~150KB | ~10KB |
| Dependencies | Many | Many | Minimal |

⚠️ = Possible but not optimized

## Smart Contract Platforms

### Supported Platforms (vrf-contract-verify)
- ✅ **NEAR Protocol**: Native integration with near-sdk
- ✅ **CosmWasm**: Cosmos SDK smart contracts
- ✅ **Generic WASM**: Any WASM-based contract platform
- 🔄 **Substrate/Polkadot**: With minimal modifications

### Not Recommended for Contracts
- ❌ **Full Libraries**: Too large, have global statics, RNG dependencies
- ❌ **Key Generation**: Should be done off-chain for security
- ❌ **Proof Creation**: Should be done by oracles/services, not contracts

## WASM Compatibility

All crates are designed for WASM environments:
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
use vrf_contract_verify::near::VrfVerifier;

#[near_bindgen]
impl RandomnessOracle {
    pub fn submit_random(&mut self, proof: Vec<u8>, round: u64) -> bool {
        let input = round.to_le_bytes();
        self.verifier.verify_vrf(proof, self.oracle_pubkey.clone(), input.to_vec())
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
```

## Building

### Smart Contract Build
```bash
cd vrf-contract-verify
cargo build --target wasm32-unknown-unknown --release --features near
```

### Web Build
```bash
cd vrf-wasm-js
wasm-pack build --target web --out-dir pkg
```

### Full Library Build
```bash
cd vrf-wasm
cargo build --target wasm32-unknown-unknown --release
```

## License

Apache-2.0 - See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`cargo test`)
4. Commit your changes (`git commit -am 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## Security

This library implements the VRF specification with:
- Constant-time operations where possible
- Secure random number generation (client-side only)
- Memory zeroization of sensitive data
- No secret-dependent branching

For smart contracts:
- Only verification is performed on-chain
- Key generation and proof creation should be done off-chain
- Consider replay attack protection in your contract logic

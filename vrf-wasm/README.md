# VRF-WASM

A WASM-compatible Verifiable Random Function (VRF) implementation based on [FastCrypto](https://github.com/MystenLabs/fastcrypto/).

FastCrypto has C dependencies (`secp256k1-sys`, `blst`) that prevent WASM compilation even when compiling with `wasm` feature flags. This library extracts only the VRF module which uses pure Rust dependencies.

## Features
- **WASM Compatible**: Runs in browsers, Node.js, and WASM workers
- **Cryptographically Secure**: ECVRF implementation following [draft-irtf-cfrg-vrf-15](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-15)
- **Lightweight**: Pure Rust, no FFI overhead ~143KB WASM binary when compiled for web
- **Flexible**: Use as Rust library or compile to WASM

## Installation

To use `vrf-wasm`, you must explicitly enable a feature flag for your target environment.

### Browser/Web Applications

```toml
[dependencies]
vrf-wasm = { version = "0.8", features = ["browser"] }
```

### NEAR Smart Contracts

```toml
[dependencies]
vrf-wasm = { version = "0.8", default-features = false, features = ["near"] }
```

If no feature is selected, you will get a compile-time error with instructions.

## Usage

### Basic VRF Operations

```rust
use vrf_wasm::ecvrf::ECVRFKeyPair;
use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
use vrf_wasm::rng::WasmRng;

// Generate a keypair
let mut rng = WasmRng::default();
let keypair = ECVRFKeyPair::generate(&mut rng);

// Create VRF proof for input
let input = b"Hello, VRF!";
let (hash, proof) = keypair.output(input);

// Verify the proof
assert!(proof.verify(input, &keypair.pk).is_ok());

// The hash is deterministic for the same key and input
let (hash2, _) = keypair.output(input);
assert_eq!(hash, hash2);

println!("VRF Hash: {}", hex::encode(hash));
```


### Deterministic KeyPair Generation

```rust
use vrf_wasm::ecvrf::ECVRFKeyPair;
use vrf_wasm::vrf::VRFKeyPair;
use vrf_wasm::rng::WasmRngFromSeed;
use rand_core::SeedableRng;

// Generate deterministic keypair from seed
let seed = [42u8; 32];
let mut rng = WasmRngFromSeed::from_seed(seed);
let keypair = ECVRFKeyPair::generate(&mut rng);

// Same seed always generates same keypair
let mut rng2 = WasmRngFromSeed::from_seed(seed);
let keypair2 = ECVRFKeyPair::generate(&mut rng2);

// Prove this by generating same VRF output
let input = b"test";
let (hash1, _) = keypair.output(input);
let (hash2, _) = keypair2.output(input);
assert_eq!(hash1, hash2);
```

### Serialization

```rust
use vrf_wasm::ecvrf::{ECVRFKeyPair, ECVRFProof, ECVRFPublicKey};
use vrf_wasm::vrf::VRFKeyPair;

// All types implement Serialize/Deserialize
let mut rng = vrf_wasm::rng::WasmRng::default();
let keypair = ECVRFKeyPair::generate(&mut rng);
let input = b"data";
let proof = keypair.prove(input);

// Serialize to bytes
let public_key_bytes = bincode::serialize(&keypair.pk).unwrap();
let proof_bytes = bincode::serialize(&proof).unwrap();

// Deserialize
let public_key: ECVRFPublicKey = bincode::deserialize(&public_key_bytes).unwrap();
let deserialized_proof: ECVRFProof = bincode::deserialize(&proof_bytes).unwrap();

// Verify still works
assert!(deserialized_proof.verify(input, &public_key).is_ok());
```

### VRF Component Extraction

For cross-verification scenarios where you need to inspect or reconstruct VRF proofs:

```rust
use vrf_wasm::ecvrf::{ECVRFKeyPair, ECVRFProof};
use vrf_wasm::vrf::VRFKeyPair;
use vrf_wasm::rng::WasmRng;

let mut rng = WasmRng::default();
let keypair = ECVRFKeyPair::generate(&mut rng);
let proof = keypair.prove(b"input");

// Extract individual components
let gamma_bytes = proof.gamma_bytes();     // [u8; 32] - compressed point
let challenge_bytes = proof.challenge_bytes(); // [u8; 16] - challenge
let scalar_bytes = proof.scalar_bytes();   // [u8; 32] - scalar

// Extract all at once
let (gamma, challenge, scalar) = proof.to_components();

// Reconstruct proof from components (for cross-verification)
let reconstructed = ECVRFProof::from_components(&gamma, &challenge, &scalar).unwrap();
assert!(reconstructed.verify(b"input", &keypair.pk).is_ok());
```

## Conditional Compilation & Feature Flags

VRF-WASM uses conditional compilation to provide optimized RNG implementations for different target environments:

### Available Features

| Feature | Target Environment | RNG Implementation | Default |
|---------|-------------------|-------------------|---------|
| `browser` | Web browsers, JavaScript | `crypto.getRandomValues()` via getrandom | ✅ Yes |
| `near` | NEAR smart contracts | `env::random_seed()` + block-based entropy + ChaCha20 | ❌ No |

### Building for Different Targets

#### Browser/JavaScript (Default)
```bash
# Default build - includes browser RNG
cargo build

# WASM for web
wasm-pack build --target web
```

#### NEAR Smart Contracts
```bash
# NEAR-specific build (NEAR features only)
cargo build --no-default-features --features near --target wasm32-unknown-unknown

# With cargo-near (recommended for NEAR contracts)
cargo install cargo-near
cargo near build
```


### Environment-Specific RNG Usage

```rust
// Generic usage (works with any feature configuration)
use vrf_wasm::rng::WasmRng;
let mut rng = WasmRng::default();

// Browser-specific (when browser feature is enabled)
use vrf_wasm::rng::BrowserWasmRng;
let mut rng = BrowserWasmRng::default();

// NEAR-specific (when near feature is enabled)
use vrf_wasm::rng::NearWasmRng;
let mut rng = NearWasmRng::default();
```


## Binary Size

| Target | Binary Size | Notes |
|--------|-------------|--------|
| Native (release) | ~2MB | Full Rust binary |
| WASM (release) | ~143KB | Optimized for web |
| WASM (compressed) | ~58KB | With Brotli compression |



## Attribution

This project is derived from [FastCrypto](https://github.com/MystenLabs/fastcrypto/) by Mysten Labs, Inc.

**Original Copyright**: Copyright (c) 2022, Mysten Labs, Inc.
**License**: Apache License 2.0
**Original Repository**: https://github.com/MystenLabs/fastcrypto/

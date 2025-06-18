# VRF-WASM

A WASM-compatible Verifiable Random Function (VRF) implementation extracted from [FastCrypto](https://github.com/MystenLabs/fastcrypto/).

FastCrypto has C dependencies (`secp256k1-sys`, `blst`) that prevent WASM compilation even when compiling with `wasm` feature flags. This library extracts only the VRF module which uses pure Rust dependencies.

## Features
- **WASM Compatible**: Runs in browsers, Node.js, and WASM workers
- **Cryptographically Secure**: ECVRF implementation following [draft-irtf-cfrg-vrf-15](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-15)
- **Lightweight**: Pure Rust, no FFI overhead ~143KB WASM binary when compiled for web
- **Flexible**: Use as Rust library or compile to WASM

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
vrf-wasm = "0.3"
curve25519-dalek-ng = { version = "4.1", default-features = false, features = ["alloc"] }
```


## Usage

### Basic VRF Operations

```rust
use vrf_wasm::ecvrf::ECVRFKeyPair;
use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
use vrf_wasm::traits::WasmRng;

// Generate a keypair
let mut rng = WasmRng;
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

### Separate Proof Generation and Verification

```rust
use vrf_wasm::ecvrf::{ECVRFKeyPair, ECVRFProof, ECVRFPublicKey};
use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
use vrf_wasm::traits::WasmRng;

// Generate keypair
let mut rng = WasmRng;
let keypair = ECVRFKeyPair::generate(&mut rng);
let public_key = keypair.pk.clone();

// Create proof
let input = b"message to sign";
let proof = keypair.prove(input);

// Verify proof (this could be done by a different party)
assert!(proof.verify(input, &public_key).is_ok());

// Extract hash from proof
let hash = proof.to_hash();
println!("VRF Output: {}", hex::encode(hash));
```

### Deterministic KeyPair Generation

```rust
use vrf_wasm::ecvrf::ECVRFKeyPair;
use vrf_wasm::vrf::VRFKeyPair;
use vrf_wasm::traits::WasmRngFromSeed;
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
let mut rng = vrf_wasm::traits::WasmRng;
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

let mut rng = WasmRng;
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
| `near` | NEAR smart contracts | Block-based entropy + ChaCha20 | ❌ No |
| `native` | Native Rust applications | OS entropy via getrandom | ❌ No |
| `deterministic` | Testing environments | Seeded ChaCha20 | ❌ No |

### Building for Different Targets

#### Browser/JavaScript (Default)
```bash
# Default build - includes browser RNG
cargo build

# Explicit browser feature
cargo build --features browser

# WASM for web
wasm-pack build --target web --features browser
```

#### NEAR Smart Contracts
```bash
# NEAR-specific build
cargo build --features near --no-default-features --target wasm32-unknown-unknown

# With cargo-near (recommended)
cargo install cargo-near
cargo near build
```

#### Native Applications
```bash
# Native-specific build
cargo build --features native --no-default-features

# Testing with deterministic RNG
cargo test --features deterministic
```

### Feature Dependencies

```toml
# In your Cargo.toml
[dependencies]
vrf-wasm = { version = "0.3", features = ["browser"] }  # Default
# or
vrf-wasm = { version = "0.3", features = ["near"], default-features = false }
# or
vrf-wasm = { version = "0.3", features = ["native"], default-features = false }
```

### RNG Implementation Details

| Component | Browser | NEAR | Native |
|-----------|---------|------|--------|
| **Entropy Source** | `crypto.getRandomValues()` | `env::random_seed()` + block context | OS entropy |
| **Algorithm** | Direct getrandom | Enhanced seed + ChaCha20 | Direct getrandom |
| **Deterministic** | ❌ No | ✅ Per-block | ❌ No |
| **Performance** | High | Medium | High |


## Cross-Platform Compatibility

### FastCrypto Compatibility
**✅ What Works Across Libraries:**
- VRF proofs generated by FastCrypto can be verified by VRF-WASM
- VRF proofs generated by VRF-WASM can be verified by FastCrypto
- VRF operations on any given key remain identical across libraries

**⚠️ What's Different:**
- **Deterministic key generation**: Same seed produces different keys
  - This only affects `WasmRngFromSeed::from_seed(seed)` vs `StdRng::from_seed(seed)`
- **Random number sequences**: ChaCha20 vs ChaCha12 have similar but distinct patterns

**💡 Migration Strategy:**
If migrating from FastCrypto and you need identical deterministic key generation, export your keys rather than relying on seed reproduction.

## Building for WASM

```bash
# Add WASM target
rustup target add wasm32-unknown-unknown

# For JavaScript/Browser (see Conditional Compilation section above)
wasm-pack build --target web --features browser

# For smart contracts (see NEAR section above)
cargo build --target wasm32-unknown-unknown --features near --no-default-features --release
```


## Performance

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

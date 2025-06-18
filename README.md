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
vrf-wasm = "0.1"
```



## Usage

### Basic VRF Operations

```rust
use vrf_wasm::ecvrf::ECVRFKeyPair;
use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
use rand::thread_rng;

// Generate a keypair
let mut rng = thread_rng();
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
use rand::thread_rng;

// Generate keypair
let mut rng = thread_rng();
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
use rand::{SeedableRng, rngs::StdRng};

// Generate deterministic keypair from seed
let seed = [42u8; 32];
let mut rng = StdRng::from_seed(seed);
let keypair = ECVRFKeyPair::generate(&mut rng);

// Same seed always generates same keypair
let mut rng2 = StdRng::from_seed(seed);
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
let keypair = ECVRFKeyPair::generate(&mut rand::thread_rng());
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

## Building for WASM

```bash
# Add WASM target
rustup target add wasm32-unknown-unknown

# Build for WASM
cargo build --target wasm32-unknown-unknown --release

# Or use wasm-pack for JavaScript bindings
# Install wasm-pack if not already installed
cargo install wasm-pack
wasm-pack build --target web --out-dir pkg
```


## Performance

| Target | Binary Size | Notes |
|--------|-------------|--------|
| Native (release) | ~2MB | Full Rust binary |
| WASM (release) | ~143KB | Optimized for web |
| WASM (compressed) | ~58KB | With Brotli compression |

## ECVRF Implementation Details

This library implements ECVRF as specified in [draft-irtf-cfrg-vrf-15](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-15) with the following parameters:

- **Curve**: Ristretto255 (built on Curve25519)
- **Hash Function**: SHA-512
- **Suite String**: `"sui_vrf"` (custom identifier)
- **Challenge Length**: 16 bytes
- **Output Length**: 64 bytes

The implementation follows the FastCrypto VRF API for compatibility while using only WASM-safe dependencies.

## Dependencies

All dependencies are pure Rust and WASM-compatible:

- `curve25519-dalek-ng` - Ristretto255 elliptic curve operations
- `sha2` / `sha3` - Cryptographic hash functions
- `elliptic-curve` - Hash-to-curve functionality
- `serde` - Serialization support
- `rand` / `getrandom` - Random number generation


## External Resources
- [Curve25519 Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
- [ECVRF Specification](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-15)

## Attribution

This project is derived from [FastCrypto](https://github.com/MystenLabs/fastcrypto/) by Mysten Labs, Inc.

**Original Copyright**: Copyright (c) 2022, Mysten Labs, Inc.
**License**: Apache License 2.0
**Original Repository**: https://github.com/MystenLabs/fastcrypto/

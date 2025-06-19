//! RFC 9381 compliant VRF verification library for NEAR smart contracts
//!
//! This library implements ECVRF-RISTRETTO255-SHA512-ELL2 as specified in RFC 9381,
//! containing only the essential components needed to verify VRF proofs.
//!
//! Client (browser wasm-worker) responsibilities:
//! - Generate VRF keypairs using vrf-wasm
//! - Create VRF outputs and proofs using vrf-wasm
//! - Send VRF output, proof, and public key to contract
//!
//! Contract responsibilities:
//! - Verify VRF proof matches the claimed output using RFC 9381 standards
//! - Use minimal cryptographic operations compatible with NEAR WASM

pub mod constants;
pub mod types;
mod verifiers;

pub use verifiers::{
    verify_vrf,
    verify_vrf_bool,
    verify_vrf_fixed
};
pub use types::{
    VrfOutput,
    VrfPublicKey,
    VrfProof,
    VerificationError
};

#[cfg(test)]
mod test;

#[cfg(all(test, feature = "near"))]
mod test_near;

//! Minimal VRF verification library for NEAR smart contracts
//!
//! This library contains only the essential components needed to verify VRF proofs,
//! without key generation, signing, or other client-side functionality.
//!
//! Client (browser wasm-worker) responsibilities:
//! - Generate VRF keypairs using vrf-wasm
//! - Create VRF outputs and proofs using vrf-wasm
//! - Send VRF output, proof, and public key to contract
//!
//! Contract responsibilities:
//! - Verify VRF proof matches the claimed output
//! - Use minimal cryptographic operations compatible with NEAR WASM

use sha2::{Digest, Sha512};
use serde::{Deserialize, Serialize};

pub use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
pub use curve25519_dalek_ng::scalar::Scalar;

/// VRF proof verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    InvalidProof,
    InvalidInput,
    InvalidPublicKey,
    InvalidProofLength,
    DecompressionFailed,
}

/// VRF public key (32 bytes - compressed point)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfPublicKey(pub [u8; 32]);


/// VRF proof (80 bytes total: 32 + 16 + 32)
// #[near_sdk::near(serializers = [borsh, json])]
// #[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct VrfProof {
    pub gamma: [u8; 32],      // 32 bytes
    pub c: [u8; 16],          // 16 bytes (challenge)
    pub s: [u8; 32],          // 32 bytes (scalar)
}

/// VRF output hash (64 bytes)
pub type VrfOutput = [u8; 64];

impl VrfProof {
    /// Verify a VRF proof against a public key and input
    pub fn verify(
        &self,
        input: &[u8],
        public_key: &VrfPublicKey,
    ) -> Result<(), VerificationError> {
        self.verify_output(input, public_key, &self.to_output())
    }

    /// Verify a VRF proof against expected output
    pub fn verify_output(
        &self,
        input: &[u8],
        public_key: &VrfPublicKey,
        expected_output: &VrfOutput,
    ) -> Result<(), VerificationError> {
        // Decompress public key
        let pk_point = CompressedRistretto(public_key.0)
            .decompress()
            .ok_or(VerificationError::DecompressionFailed)?;

        // Decompress gamma
        let gamma = CompressedRistretto(self.gamma)
            .decompress()
            .ok_or(VerificationError::DecompressionFailed)?;

        // Decode scalar s
        let s = Scalar::from_canonical_bytes(self.s)
            .unwrap_or(Scalar::zero());

        // Hash to curve
        let h = hash_to_curve(&pk_point, input);

        // Reconstruct challenge
        let challenge = challenge_from_bytes(&self.c);

        // Verification equations:
        // u = s*G - c*PK
        // v = s*H - c*Gamma
        let u = RistrettoPoint::vartime_double_scalar_mul_basepoint(&challenge, &(-pk_point), &s);
        let v = &s * &h - &challenge * &gamma;

        // Recompute challenge
        let c_prime = generate_challenge(&pk_point, &h, &gamma, &u, &v);

        if c_prime != self.c {
            return Err(VerificationError::InvalidProof);
        }

        // Verify output matches
        let computed_output = proof_to_hash(&gamma);
        if computed_output != *expected_output {
            return Err(VerificationError::InvalidProof);
        }

        Ok(())
    }

    /// Convert proof to VRF output
    pub fn to_output(&self) -> VrfOutput {
        let gamma = CompressedRistretto(self.gamma)
            .decompress()
            .expect("Invalid gamma in proof");
        proof_to_hash(&gamma)
    }
}

// Minimal internal functions for verification only
fn hash_to_curve(pk: &RistrettoPoint, input: &[u8]) -> RistrettoPoint {
    use sha2::{Sha512, Digest};

    let mut hasher = Sha512::new();
    hasher.update(b"ECVRF_ristretto255_XMD:SHA-512_R255MAP_RO_sui_vrf");
    hasher.update(&pk.compress().0);
    hasher.update(input);
    let hash = hasher.finalize();

    RistrettoPoint::from_uniform_bytes(&hash.into())
}

fn challenge_from_bytes(bytes: &[u8; 16]) -> Scalar {
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[..16].copy_from_slice(bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

fn generate_challenge(
    pk: &RistrettoPoint,
    h: &RistrettoPoint,
    gamma: &RistrettoPoint,
    u: &RistrettoPoint,
    v: &RistrettoPoint,
) -> [u8; 16] {
    let mut hasher = Sha512::new();
    hasher.update(b"sui_vrf");
    hasher.update([0x02]);
    hasher.update(&pk.compress().0);
    hasher.update(&h.compress().0);
    hasher.update(&gamma.compress().0);
    hasher.update(&u.compress().0);
    hasher.update(&v.compress().0);
    hasher.update([0x00]);
    let hash = hasher.finalize();

    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&hash[..16]);
    challenge
}

fn proof_to_hash(gamma: &RistrettoPoint) -> VrfOutput {
    let mut hasher = Sha512::new();
    hasher.update(b"near_vrf");
    hasher.update([0x03]);
    hasher.update(&gamma.compress().0);
    hasher.update([0x00]);
    hasher.finalize().into()
}

pub mod near_vrf_verifier {
    use super::*;

    pub fn verify_vrf(
        proof_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
        input: Vec<u8>,
    ) -> bool {
        if public_key_bytes.len() != 32 || proof_bytes.len() != 80 {
            return false;
        }

        let public_key = VrfPublicKey(public_key_bytes.try_into().unwrap());
        let proof: VrfProof = VrfProof {
            gamma: proof_bytes[0..32].try_into().unwrap(),
            c: proof_bytes[32..48].try_into().unwrap(),
            s: proof_bytes[48..80].try_into().unwrap(),
        };

        proof.verify(&input, &public_key).is_ok()
    }
}
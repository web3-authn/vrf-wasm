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

use sha2::{Digest, Sha512};

pub use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
pub use curve25519_dalek_ng::scalar::Scalar;

// RFC 9381 compliant domain separation constants
// Following ECVRF-RISTRETTO255-SHA512-ELL2 specification
const VRF_VERSION: &str = "2.0";

// RFC 9381 compliant domain separation tags (DST)
// Format: "ECVRF_" + h2c_suite_ID_string + "_" + suite_string
// Suite string matching the main vrf-wasm library
const SUITE_STRING: &[u8; 7] = b"sui_vrf";
// Domain separator bytes matching draft-irtf-cfrg-vrf-15 specification
const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT: u8 = 0x02;
const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK: u8 = 0x00;
const PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT: u8 = 0x03;
const PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

// RFC 9381 compliant domain separation tags (DST) for hash-to-curve
const VRF_HASH_TO_CURVE_DOMAIN: &[u8] = b"ECVRF_ristretto255_XMD:SHA-512_R255MAP_RO_sui_vrf";

// RFC 9381 constants
const CHALLENGE_LENGTH: usize = 16;  // RFC 9381: challenge is 16 bytes
const EXPAND_MESSAGE_OUTPUT_LENGTH: usize = 64;  // SHA-512 output size for expand_message_xmd

/// Validate domain separation version (for future compatibility)
pub fn get_vrf_version() -> &'static str {
    VRF_VERSION
}

/// VRF proof verification result
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// VRF public key (32 bytes - compressed point)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfPublicKey(pub [u8; 32]);

impl VrfPublicKey {
    /// Validate public key according to RFC 9381
    /// Check for zero point and ensure valid curve point
    pub fn validate(&self) -> Result<RistrettoPoint, VerificationError> {
        // Check for zero public key
        if self.0.iter().all(|&b| b == 0) {
            return Err(VerificationError::ZeroPublicKey);
        }

        // Decompress and validate curve point
        let pk_point = CompressedRistretto(self.0)
            .decompress()
            .ok_or(VerificationError::InvalidPublicKey)?;

        // Additional check: ensure not identity point (zero point on curve)
        if pk_point == RistrettoPoint::default() {
            return Err(VerificationError::ZeroPublicKey);
        }

        Ok(pk_point)
    }
}

/// RFC 9381 compliant VRF proof (80 bytes total: 32 + 16 + 32)
#[cfg_attr(feature = "near", near_sdk::near(serializers = [borsh, json]))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfProof {
    pub gamma: [u8; 32],            // 32 bytes (VRF output point)
    pub c: [u8; CHALLENGE_LENGTH],  // 16 bytes (RFC 9381 challenge)
    pub s: [u8; 32],                // 32 bytes (scalar)
}

/// VRF output hash (64 bytes)
pub type VrfOutput = [u8; 64];

impl VrfProof {
    /// Verify a VRF proof against a public key and input
    pub fn verify(
        &self,
        input: &[u8],
        public_key: &VrfPublicKey,
    ) -> Result<VrfOutput, VerificationError> {
        let output = self.to_output()?;
        self.verify_output(input, public_key, &output)?;
        Ok(output)
    }

    /// Verify a VRF proof against expected output
    pub fn verify_output(
        &self,
        input: &[u8],
        public_key: &VrfPublicKey,
        expected_output: &VrfOutput,
    ) -> Result<(), VerificationError> {
        // Validate and decompress public key
        let pk_point = public_key.validate()?;

        // Decompress gamma
        let gamma = CompressedRistretto(self.gamma)
            .decompress()
            .ok_or(VerificationError::DecompressionFailed)?;

        // Decode scalar s - use canonical bytes check
        let s = Scalar::from_canonical_bytes(self.s)
            .ok_or(VerificationError::InvalidScalar)?;

        // RFC 9381 compliant hash to curve
        let h = hash_to_curve(&pk_point, input)?;

        // Convert challenge from 16-byte challenge to scalar
        let challenge = challenge_from_hash(&self.c);

        // Verification equations:
        // u = s*G - c*PK
        // v = s*H - c*Gamma
        use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
        let u = &s * &RISTRETTO_BASEPOINT_POINT - &challenge * &pk_point;
        let v = &s * &h - &challenge * &gamma;

        // Recompute challenge
        let c_prime = generate_challenge(&pk_point, &h, &gamma, &u, &v)?;

        // Compare challenge values (16 bytes)
        if c_prime != self.c {
            return Err(VerificationError::InvalidProof);
        }

        // Verify output matches
        let computed_output = proof_to_hash(&gamma)?;
        if computed_output != *expected_output {
            return Err(VerificationError::InvalidProof);
        }

        Ok(())
    }

    /// Convert proof to VRF output - now returns Result to avoid panics
    pub fn to_output(&self) -> Result<VrfOutput, VerificationError> {
        let gamma = CompressedRistretto(self.gamma)
            .decompress()
            .ok_or(VerificationError::InvalidGamma)?;
        proof_to_hash(&gamma)
    }
}

// RFC 9381 compliant functions for verification only

/// RFC 9381 compliant expand_message_xmd implementation for hash-to-curve
/// Following ECVRF-RISTRETTO255-SHA512-ELL2 specification
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, VerificationError> {
    let b_in_bytes = 64; // SHA-512 block size
    let r_in_bytes = 64; // SHA-512 output size

    if len_in_bytes >= (1 << 16) || dst.len() > 255 {
        return Err(VerificationError::ExpandMessageXmdFailed);
    }

    let ell = (len_in_bytes + r_in_bytes - 1) / r_in_bytes;
    if ell >= 256 {
        return Err(VerificationError::ExpandMessageXmdFailed);
    }

    let dst_prime = {
        let mut dst_prime = dst.to_vec();
        dst_prime.push(dst.len() as u8);
        dst_prime
    };

    let z_pad = vec![0u8; b_in_bytes];
    let l_i_b_str = [(len_in_bytes >> 8) as u8, len_in_bytes as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut hasher = Sha512::new();
    hasher.update(&z_pad);
    hasher.update(msg);
    hasher.update(&l_i_b_str);
    hasher.update([0u8]);
    hasher.update(&dst_prime);
    let b_0 = hasher.finalize();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut hasher = Sha512::new();
    hasher.update(&b_0);
    hasher.update([1u8]);
    hasher.update(&dst_prime);
    let mut b_i = hasher.finalize();

    let mut uniform_bytes = b_i.to_vec();

    for i in 2..=ell {
        // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
        let mut strxor_input = b_0.clone();
        for (j, &byte) in b_i.iter().enumerate() {
            strxor_input[j] ^= byte;
        }

        let mut hasher = Sha512::new();
        hasher.update(&strxor_input);
        hasher.update([i as u8]);
        hasher.update(&dst_prime);
        b_i = hasher.finalize();

        uniform_bytes.extend_from_slice(&b_i);
    }

    uniform_bytes.truncate(len_in_bytes);
    Ok(uniform_bytes)
}

/// RFC 9381 compliant hash-to-curve implementation
fn hash_to_curve(pk: &RistrettoPoint, input: &[u8]) -> Result<RistrettoPoint, VerificationError> {
    // Construct message: compressed public key || input
    let mut msg = Vec::new();
    msg.extend_from_slice(&pk.compress().0);
    msg.extend_from_slice(input);

    // Use expand_message_xmd with RFC-compliant DST
    let uniform_bytes = expand_message_xmd(&msg, VRF_HASH_TO_CURVE_DOMAIN, EXPAND_MESSAGE_OUTPUT_LENGTH)?;

    // Convert to fixed-size array for from_uniform_bytes
    let mut uniform_array = [0u8; EXPAND_MESSAGE_OUTPUT_LENGTH];
    uniform_array.copy_from_slice(&uniform_bytes);

    Ok(RistrettoPoint::from_uniform_bytes(&uniform_array))
}

/// RFC 9381 compliant challenge generation from 16-byte hash
fn challenge_from_hash(hash: &[u8; CHALLENGE_LENGTH]) -> Scalar {
    // Pad 16-byte challenge to 32 bytes for scalar conversion
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes[..CHALLENGE_LENGTH].copy_from_slice(hash);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

/// RFC 9381 compliant challenge generation (returns 16 bytes)
/// Matches the implementation in the main vrf-wasm library
fn generate_challenge(
    pk: &RistrettoPoint,
    h: &RistrettoPoint,
    gamma: &RistrettoPoint,
    u: &RistrettoPoint,
    v: &RistrettoPoint,
) -> Result<[u8; CHALLENGE_LENGTH], VerificationError> {
    let mut hasher = Sha512::new();
    hasher.update(SUITE_STRING);
    hasher.update([CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT]);
    hasher.update(&pk.compress().0);
    hasher.update(&h.compress().0);
    hasher.update(&gamma.compress().0);
    hasher.update(&u.compress().0);
    hasher.update(&v.compress().0);
    hasher.update([CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK]);
    let hash = hasher.finalize();

    // RFC 9381: challenge is first 16 bytes of hash
    let mut challenge = [0u8; CHALLENGE_LENGTH];
    challenge.copy_from_slice(&hash[..CHALLENGE_LENGTH]);
    Ok(challenge)
}

/// RFC 9381 compliant VRF output generation
/// Matches the implementation in the main vrf-wasm library
fn proof_to_hash(gamma: &RistrettoPoint) -> Result<VrfOutput, VerificationError> {
    let mut hasher = Sha512::new();
    hasher.update(SUITE_STRING);
    hasher.update([PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT]);
    hasher.update(&gamma.compress().0);
    hasher.update([PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK]);
    Ok(hasher.finalize().into())
}

pub mod near_vrf_verifier {
    use super::*;

    // RFC 9381 proof length: gamma(32) + c(16) + s(32) = 80 bytes
    const RFC_VRF_PROOF_LENGTH: usize = 32 + CHALLENGE_LENGTH + 32; // 80 bytes

    /// Safe VRF verification function for NEAR contracts (with fixed-length arrays)
    /// Returns the VRF output on successful verification
    pub fn verify_vrf_fixed(
        proof_bytes: &[u8; RFC_VRF_PROOF_LENGTH],    // RFC 9381: 80 bytes
        public_key_bytes: &[u8; 32],                 // Fixed-length for better type safety
        input: &[u8],
    ) -> Result<VrfOutput, VerificationError> {
        let public_key = VrfPublicKey(*public_key_bytes);

        // Parse RFC 9381 proof structure: gamma(32) + c(16) + s(32)
        let proof = VrfProof {
            gamma: proof_bytes[0..32].try_into()
                .map_err(|_| VerificationError::InvalidProofLength)?,
            c: proof_bytes[32..(32 + CHALLENGE_LENGTH)].try_into()
                .map_err(|_| VerificationError::InvalidProofLength)?,
            s: proof_bytes[(32 + CHALLENGE_LENGTH)..RFC_VRF_PROOF_LENGTH].try_into()
                .map_err(|_| VerificationError::InvalidProofLength)?,
        };

        proof.verify(input, &public_key)
    }

    /// Safe VRF verification function for NEAR contracts (Vec input for compatibility)
    /// Returns the VRF output on successful verification
    pub fn verify_vrf(
        proof_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
        input: Vec<u8>,
    ) -> Result<VrfOutput, VerificationError> {
        if public_key_bytes.len() != 32 {
            return Err(VerificationError::InvalidPublicKey);
        }

        if proof_bytes.len() != RFC_VRF_PROOF_LENGTH {  // RFC 9381: 80 bytes
            return Err(VerificationError::InvalidProofLength);
        }

        let public_key_array: [u8; 32] = public_key_bytes.try_into()
            .map_err(|_| VerificationError::InvalidPublicKey)?;
        let proof_array: [u8; RFC_VRF_PROOF_LENGTH] = proof_bytes.try_into()
            .map_err(|_| VerificationError::InvalidProofLength)?;

        verify_vrf_fixed(&proof_array, &public_key_array, &input)
    }

    /// Boolean verification for simpler contract usage
    pub fn verify_vrf_bool(
        proof_bytes: Vec<u8>,
        public_key_bytes: Vec<u8>,
        input: Vec<u8>,
    ) -> bool {
        verify_vrf(proof_bytes, public_key_bytes, input).is_ok()
    }
}
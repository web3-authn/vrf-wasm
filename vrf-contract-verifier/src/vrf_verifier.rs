use crate::constants::{
    CHALLENGE_LENGTH,
    VRF_HASH_TO_CURVE_DOMAIN,
    EXPAND_MESSAGE_OUTPUT_LENGTH,
    SUITE_STRING,
    CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT,
    CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK,
    PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT,
    PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK
};
use sha2::{Digest, Sha512};


pub use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
pub use curve25519_dalek_ng::scalar::Scalar;

// Import the same expand_message_xmd as vrf-wasm
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXmd, Expander};


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

/// RFC 9381 compliant hash-to-curve implementation
/// Uses the same expand_message_xmd as vrf-wasm for perfect compatibility
pub fn hash_to_curve(pk: &RistrettoPoint, input: &[u8]) -> Result<RistrettoPoint, VerificationError> {
    let pk_compressed = pk.compress().0;

    // Use the same expand_message_xmd as vrf-wasm
    let mut expanded_message = ExpandMsgXmd::<Sha512>::expand_message(
        &[&pk_compressed, input],
        &[VRF_HASH_TO_CURVE_DOMAIN],
        EXPAND_MESSAGE_OUTPUT_LENGTH,
    )
    .map_err(|_| VerificationError::ExpandMessageXmdFailed)?;

    let mut uniform_bytes = [0u8; EXPAND_MESSAGE_OUTPUT_LENGTH];
    expanded_message.fill_bytes(&mut uniform_bytes);

    Ok(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
}

/// RFC 9381 compliant challenge generation from 16-byte hash
pub fn challenge_from_hash(hash: &[u8; CHALLENGE_LENGTH]) -> Scalar {
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

    let pk_bytes = pk.compress().0;
    let h_bytes = h.compress().0;
    let gamma_bytes = gamma.compress().0;
    let u_bytes = u.compress().0;
    let v_bytes = v.compress().0;

    hasher.update(SUITE_STRING);
    hasher.update([CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT]);
    hasher.update(pk_bytes);
    hasher.update(h_bytes);
    hasher.update(gamma_bytes);
    hasher.update(u_bytes);
    hasher.update(v_bytes);
    hasher.update([CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK]);
    let hash = hasher.finalize();

    // RFC 9381: challenge is first 16 bytes of hash
    let mut challenge = [0u8; CHALLENGE_LENGTH];
    challenge.copy_from_slice(&hash[..CHALLENGE_LENGTH]);

    Ok(challenge)
}

/// RFC 9381 compliant VRF output generation
/// Matches the implementation in the main vrf-wasm library
pub fn proof_to_hash(gamma: &RistrettoPoint) -> Result<VrfOutput, VerificationError> {
    let mut hasher = Sha512::new();
    hasher.update(SUITE_STRING);
    hasher.update([PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT]);
    hasher.update(&gamma.compress().0);
    hasher.update([PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK]);
    Ok(hasher.finalize().into())
}
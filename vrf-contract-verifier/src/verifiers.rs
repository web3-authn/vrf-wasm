use crate::constants::CHALLENGE_LENGTH;
use crate::types::{VrfOutput, VrfPublicKey, VrfProof, VerificationError};

// RFC 9381 proof length: gamma(32) + c(16) + s(32) = 80 bytes
const RFC_VRF_PROOF_LENGTH: usize = 32 + CHALLENGE_LENGTH + 32; // 80 bytes

/// VRF verification function for NEAR contracts (with fixed-length arrays)
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

/// VRF verification function for NEAR contracts (Vec input for compatibility)
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
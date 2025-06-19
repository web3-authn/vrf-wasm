
// RFC 9381 compliant domain separation constants
// Following ECVRF-RISTRETTO255-SHA512-ELL2 specification
pub const VRF_VERSION: &str = "2.0";

// RFC 9381 compliant domain separation tags (DST)
// Format: "ECVRF_" + h2c_suite_ID_string + "_" + suite_string
// Suite string matching the main vrf-wasm library
pub const SUITE_STRING: &[u8; 7] = b"sui_vrf";
// Domain separator bytes matching draft-irtf-cfrg-vrf-15 specification
pub const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_FRONT: u8 = 0x02;
pub const CHALLENGE_GENERATION_DOMAIN_SEPARATOR_BACK: u8 = 0x00;
pub const PROOF_TO_HASH_DOMAIN_SEPARATOR_FRONT: u8 = 0x03;
pub const PROOF_TO_HASH_DOMAIN_SEPARATOR_BACK: u8 = 0x00;

// RFC 9381 compliant domain separation tags (DST) for hash-to-curve
pub const VRF_HASH_TO_CURVE_DOMAIN: &[u8] = b"ECVRF_ristretto255_XMD:SHA-512_R255MAP_RO_sui_vrf";

// RFC 9381 constants
pub const CHALLENGE_LENGTH: usize = 16;  // RFC 9381: challenge is 16 bytes
pub const EXPAND_MESSAGE_OUTPUT_LENGTH: usize = 64;  // SHA-512 output size for expand_message_xmd

/// Validate domain separation version (for future compatibility)
pub fn get_vrf_version() -> &'static str {
    VRF_VERSION
}
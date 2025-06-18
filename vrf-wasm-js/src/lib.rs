
use wasm_bindgen::prelude::*;
use vrf_wasm::{
    ecvrf::{ECVRFKeyPair, ECVRFPublicKey, ECVRFProof},
    traits::{WasmRng, WasmRngFromSeed},
    vrf::{VRFKeyPair, VRFProof},
};

// Initialize panic hook for better error messages in the browser
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

/// JavaScript-compatible VRF KeyPair wrapper
#[wasm_bindgen]
pub struct VRFKeyPairJS {
    inner: ECVRFKeyPair,
}

#[wasm_bindgen]
impl VRFKeyPairJS {
    /// Generate a new VRF keypair
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<VRFKeyPairJS, JsValue> {
        let mut rng = WasmRng;
        let keypair = ECVRFKeyPair::generate(&mut rng);

        Ok(VRFKeyPairJS { inner: keypair })
    }

    /// Get the public key as bytes
    #[wasm_bindgen(js_name = "getPublicKey")]
    pub fn get_public_key(&self) -> Result<Vec<u8>, JsValue> {
        bincode::serialize(&self.inner.pk)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize public key: {}", e)))
    }

    /// Generate a VRF proof for the given input
    #[wasm_bindgen(js_name = "prove")]
    pub fn prove(&self, input: &[u8]) -> Result<Vec<u8>, JsValue> {
        let proof = self.inner.prove(input);
        bincode::serialize(&proof)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof: {}", e)))
    }

    /// Generate both hash and proof for the given input
    #[wasm_bindgen(js_name = "output")]
    pub fn output(&self, input: &[u8]) -> Result<VRFOutputJS, JsValue> {
        let (hash, proof) = self.inner.output(input);
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof: {}", e)))?;

        Ok(VRFOutputJS {
            hash: hash.to_vec(),
            proof: proof_bytes,
        })
    }
}

/// JavaScript-compatible VRF output containing both hash and proof
#[wasm_bindgen]
pub struct VRFOutputJS {
    hash: Vec<u8>,
    proof: Vec<u8>,
}

#[wasm_bindgen]
impl VRFOutputJS {
    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.hash.as_slice())
    }

    #[wasm_bindgen(getter)]
    pub fn proof(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.proof.as_slice())
    }
}

/// Verify a VRF proof
#[wasm_bindgen(js_name = "verifyProof")]
pub fn verify_proof(
    public_key_bytes: &[u8],
    input: &[u8],
    proof_bytes: &[u8],
) -> Result<bool, JsValue> {
    let public_key: ECVRFPublicKey = bincode::deserialize(public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {}", e)))?;

    let proof: ECVRFProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    match proof.verify(input, &public_key) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Extract hash from a VRF proof
#[wasm_bindgen(js_name = "proofToHash")]
pub fn proof_to_hash(proof_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let proof: ECVRFProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    Ok(proof.to_hash().to_vec())
}

/// Verify a VRF proof and its corresponding output hash
#[wasm_bindgen(js_name = "verifyOutput")]
pub fn verify_output(
    public_key_bytes: &[u8],
    input: &[u8],
    proof_bytes: &[u8],
    expected_hash: &[u8],
) -> Result<bool, JsValue> {
    let public_key: ECVRFPublicKey = bincode::deserialize(public_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {}", e)))?;

    let proof: ECVRFProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    // Convert expected_hash to fixed-size array
    if expected_hash.len() != 64 {
        return Err(JsValue::from_str("Expected hash must be 64 bytes"));
    }

    let mut hash_array = [0u8; 64];
    hash_array.copy_from_slice(expected_hash);

    match proof.verify_output(input, &public_key, &hash_array) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Utility function to create a VRF keypair from a seed (for deterministic generation)
#[wasm_bindgen(js_name = "keyPairFromSeed")]
pub fn keypair_from_seed(seed: &[u8]) -> Result<VRFKeyPairJS, JsValue> {
    if seed.len() < 32 {
        return Err(JsValue::from_str("Seed must be at least 32 bytes"));
    }

    // For deterministic generation, we'll use the seed directly to generate the keypair
    // This is a simplified approach - in production you might want a more sophisticated
    // key derivation function
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed[..32]);

    // Create a deterministic RNG from the seed
    use rand_core::SeedableRng;
    let mut rng = WasmRngFromSeed::from_seed(seed_array);
    let keypair = ECVRFKeyPair::generate(&mut rng);

    Ok(VRFKeyPairJS { inner: keypair })
}

/// Extract gamma component from a VRF proof (32 bytes)
#[wasm_bindgen(js_name = "extractGamma")]
pub fn extract_gamma(proof_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let proof: ECVRFProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    Ok(proof.gamma_bytes().to_vec())
}

/// Extract challenge component from a VRF proof (16 bytes)
#[wasm_bindgen(js_name = "extractChallenge")]
pub fn extract_challenge(proof_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let proof: ECVRFProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    Ok(proof.challenge_bytes().to_vec())
}

/// Extract scalar component from a VRF proof (32 bytes)
#[wasm_bindgen(js_name = "extractScalar")]
pub fn extract_scalar(proof_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let proof: ECVRFProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    Ok(proof.scalar_bytes().to_vec())
}

/// Extract all components from a VRF proof
#[wasm_bindgen(js_name = "extractComponents")]
pub fn extract_components(proof_bytes: &[u8]) -> Result<VRFComponentsJS, JsValue> {
    let proof: ECVRFProof = bincode::deserialize(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    let (gamma, challenge, scalar) = proof.to_components();

    Ok(VRFComponentsJS {
        gamma: gamma.to_vec(),
        challenge: challenge.to_vec(),
        scalar: scalar.to_vec(),
    })
}

/// Create a VRF proof from individual components
#[wasm_bindgen(js_name = "createProofFromComponents")]
pub fn create_proof_from_components(
    gamma_bytes: &[u8],
    challenge_bytes: &[u8],
    scalar_bytes: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if gamma_bytes.len() != 32 {
        return Err(JsValue::from_str("Gamma must be 32 bytes"));
    }
    if challenge_bytes.len() != 16 {
        return Err(JsValue::from_str("Challenge must be 16 bytes"));
    }
    if scalar_bytes.len() != 32 {
        return Err(JsValue::from_str("Scalar must be 32 bytes"));
    }

    let gamma_array: [u8; 32] = gamma_bytes.try_into()
        .map_err(|_| JsValue::from_str("Invalid gamma length"))?;
    let challenge_array: [u8; 16] = challenge_bytes.try_into()
        .map_err(|_| JsValue::from_str("Invalid challenge length"))?;
    let scalar_array: [u8; 32] = scalar_bytes.try_into()
        .map_err(|_| JsValue::from_str("Invalid scalar length"))?;

    let proof = ECVRFProof::from_components(&gamma_array, &challenge_array, &scalar_array)
        .map_err(|e| JsValue::from_str(&format!("Failed to create proof: {}", e)))?;

    bincode::serialize(&proof)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize proof: {}", e)))
}

/// JavaScript-compatible VRF proof components
#[wasm_bindgen]
pub struct VRFComponentsJS {
    gamma: Vec<u8>,
    challenge: Vec<u8>,
    scalar: Vec<u8>,
}

#[wasm_bindgen]
impl VRFComponentsJS {
    #[wasm_bindgen(getter)]
    pub fn gamma(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.gamma.as_slice())
    }

    #[wasm_bindgen(getter)]
    pub fn challenge(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.challenge.as_slice())
    }

    #[wasm_bindgen(getter)]
    pub fn scalar(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(self.scalar.as_slice())
    }
}

/// Get the version of the VRF-WASM library
#[wasm_bindgen(js_name = "getVersion")]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// Export types for TypeScript
#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
export class VRFKeyPairJS {
    constructor();
    getPublicKey(): Uint8Array;
    prove(input: Uint8Array): Uint8Array;
    output(input: Uint8Array): VRFOutputJS;
}

export class VRFOutputJS {
    readonly hash: Uint8Array;
    readonly proof: Uint8Array;
}

export class VRFComponentsJS {
    readonly gamma: Uint8Array;
    readonly challenge: Uint8Array;
    readonly scalar: Uint8Array;
}

export function verifyProof(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array
): boolean;

export function proofToHash(proof: Uint8Array): Uint8Array;

export function verifyOutput(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    expectedHash: Uint8Array
): boolean;

export function keyPairFromSeed(seed: Uint8Array): VRFKeyPairJS;

export function extractGamma(proof: Uint8Array): Uint8Array;

export function extractChallenge(proof: Uint8Array): Uint8Array;

export function extractScalar(proof: Uint8Array): Uint8Array;

export function extractComponents(proof: Uint8Array): VRFComponentsJS;

export function createProofFromComponents(
    gamma: Uint8Array,
    challenge: Uint8Array,
    scalar: Uint8Array
): Uint8Array;

export function getVersion(): string;
"#;
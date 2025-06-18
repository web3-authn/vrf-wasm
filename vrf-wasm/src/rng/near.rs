//! NEAR smart contract RNG implementation using block-based entropy

use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use crate::traits::AllowedRng;

/// NEAR smart contract RNG using block-based entropy
pub struct WasmRng {
    state: rand_chacha::ChaCha20Rng,
    block_height_used: u64,
}

impl WasmRng {
    /// Create a new NEAR RNG instance
    pub fn new() -> Self {
        let random_seed = near_sdk::env::random_seed();
        let block_height = near_sdk::env::block_height();

        // Enhance entropy by combining random_seed with block info
        let mut enhanced_seed = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&random_seed);
        hasher.update(block_height.to_le_bytes());
        hasher.update(near_sdk::env::predecessor_account_id().as_bytes());
        enhanced_seed.copy_from_slice(&hasher.finalize());

        Self {
            state: rand_chacha::ChaCha20Rng::from_seed(enhanced_seed),
            block_height_used: block_height,
        }
    }

    /// Refresh the RNG state if we're in a new block
    fn refresh_if_needed(&mut self) {
        let current_height = near_sdk::env::block_height();
        // Refresh state if we're in a new block
        if current_height != self.block_height_used {
            *self = Self::new();
        }
    }
}

impl CryptoRng for WasmRng {}

impl RngCore for WasmRng {
    fn next_u32(&mut self) -> u32 {
        self.refresh_if_needed();
        self.state.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.refresh_if_needed();
        self.state.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.refresh_if_needed();
        self.state.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.refresh_if_needed();
        self.state.try_fill_bytes(dest)
    }
}

impl Default for WasmRng {
    fn default() -> Self {
        Self::new()
    }
}

impl AllowedRng for WasmRng {}

/// WASM-compatible seeded RNG using ChaCha20 for deterministic operations
pub type WasmRngFromSeed = rand_chacha::ChaCha20Rng;

impl AllowedRng for WasmRngFromSeed {}
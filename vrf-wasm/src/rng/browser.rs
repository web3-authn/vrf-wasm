//! Browser-specific RNG implementation using crypto.getRandomValues()

use getrandom::getrandom;
use rand_core::{CryptoRng, RngCore};
use crate::traits::AllowedRng;

/// Browser-compatible RNG using crypto.getRandomValues()
pub struct WasmRng;

impl CryptoRng for WasmRng {}

impl RngCore for WasmRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom(dest).expect("getrandom failed in browser environment");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        // getrandom doesn't provide a fallible interface in WASM/browser context
        // Fall back to fill_bytes which will panic on failure
        self.fill_bytes(dest);
        Ok(())
    }
}

impl AllowedRng for WasmRng {}

/// WASM-compatible seeded RNG using ChaCha20 for deterministic operations
pub type WasmRngFromSeed = rand_chacha::ChaCha20Rng;

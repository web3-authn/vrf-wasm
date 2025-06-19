//! Random number generation implementations for different target environments.
//!
//! This module provides conditional compilation for RNG implementations:
//! - Browser: Uses crypto.getRandomValues() via getrandom with "js" feature
//! - NEAR: Uses env::random_seed() with enhanced entropy via ChaCha20

// Always compile all available modules when their features are enabled
#[cfg(feature = "browser")]
pub mod browser;

#[cfg(feature = "near")]
pub mod near;

// Export implementation-specific types
#[cfg(feature = "browser")]
pub use browser::{WasmRng as BrowserWasmRng, WasmRngFromSeed as BrowserWasmRngFromSeed};

#[cfg(feature = "near")]
pub use near::{WasmRng as NearWasmRng, WasmRngFromSeed as NearWasmRngFromSeed};

// Default exports with priority system for backward compatibility
#[cfg(feature = "browser")]
pub use browser::{WasmRng, WasmRngFromSeed};

#[cfg(all(feature = "near", not(feature = "browser")))]
pub use near::{WasmRng, WasmRngFromSeed};

// Re-export rand_core traits for consistency
pub use rand_core::{CryptoRng, RngCore};

/// Get the current default RNG implementation name
pub fn get_rng_implementation() -> &'static str {
    #[cfg(feature = "browser")]
    {
        "browser"
    }
    #[cfg(all(feature = "near", not(feature = "browser")))]
    {
        "near"
    }
}
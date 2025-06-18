//! Random number generation implementations for different target environments.
//!
//! This module provides conditional compilation for RNG implementations:
//! - Browser: Uses crypto.getRandomValues() via getrandom with "js" feature
//! - NEAR: Uses env::random_seed() with enhanced entropy via ChaCha20
//! - Native: Uses OS entropy via getrandom (future extension)

// Conditional imports based on target environment
#[cfg(feature = "browser")]
mod browser;
#[cfg(feature = "browser")]
pub use browser::{WasmRng, WasmRngFromSeed};

#[cfg(feature = "near")]
mod near;
#[cfg(feature = "near")]
pub use near::{WasmRng, WasmRngFromSeed};

// Future extension for native environments
#[cfg(feature = "native")]
mod native;
#[cfg(feature = "native")]
pub use native::{WasmRng, WasmRngFromSeed};

// Re-export rand_core traits for consistency
pub use rand_core::{CryptoRng, RngCore};

/// Get the current RNG implementation name for testing/debugging
pub fn get_rng_implementation() -> &'static str {
    #[cfg(feature = "browser")]
    {
        "browser"
    }
    #[cfg(all(feature = "near", not(feature = "browser")))]
    {
        "near"
    }
    #[cfg(all(feature = "native", not(feature = "browser"), not(feature = "near")))]
    {
        "native"
    }
    #[cfg(all(not(feature = "browser"), not(feature = "near"), not(feature = "native")))]
    {
        "none"
    }
}
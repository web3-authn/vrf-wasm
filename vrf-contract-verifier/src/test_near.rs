//! Test NEAR contract to verify that vrf-contract-verifier compiles correctly in NEAR environment
//!
//! This module is only compiled when the "near" feature is enabled to test
//! compatibility with the NEAR smart contract environment.

#[cfg(all(test, feature = "near"))]
mod near_contract_tests {
    use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
    use near_sdk::{near_bindgen, env, log, AccountId};
    use crate::{verify_vrf, verify_vrf_bool};

    /// Basic NEAR contract for testing VRF verification
    #[near_bindgen]
    #[derive(BorshDeserialize, BorshSerialize, Default)]
    pub struct VrfTestContract {
        /// Counter of successful verifications
        pub successful_verifications: u64,
        /// Counter of failed verifications
        pub failed_verifications: u64,
    }

    #[near_bindgen]
    impl VrfTestContract {
        /// Initialize a new contract
        #[init]
        pub fn new() -> Self {
            Self {
                successful_verifications: 0,
                failed_verifications: 0,
            }
        }

        /// Verify a VRF proof and return the VRF output
        ///
        /// # Arguments
        /// * `proof_bytes` - The 80-byte VRF proof (gamma + challenge + scalar)
        /// * `public_key_bytes` - The 32-byte public key
        /// * `input` - The input data that was used to generate the proof
        ///
        /// # Returns
        /// The 64-byte VRF output on success, or panics on verification failure
        pub fn verify_vrf_proof(
            &mut self,
            proof_bytes: Vec<u8>,
            public_key_bytes: Vec<u8>,
            input: Vec<u8>,
        ) -> Vec<u8> {
            // Log the verification attempt
            log!("Attempting VRF verification with proof length: {}, pk length: {}, input length: {}",
                 proof_bytes.len(), public_key_bytes.len(), input.len());

            // Verify the VRF proof using our verifier
            match verify_vrf(proof_bytes, public_key_bytes, input) {
                Ok(vrf_output) => {
                    self.successful_verifications += 1;
                    log!("VRF verification successful! Output: {:?}", &vrf_output[..8]);
                    vrf_output.to_vec()
                }
                Err(e) => {
                    self.failed_verifications += 1;
                    let error_msg = format!("VRF verification failed: {:?}", e);
                    log!("VRF verification failed: {:?}", e);
                    env::panic_str(&error_msg);
                }
            }
        }

        /// Boolean VRF verification (doesn't panic on failure)
        ///
        /// # Arguments
        /// * `proof_bytes` - The 80-byte VRF proof
        /// * `public_key_bytes` - The 32-byte public key
        /// * `input` - The input data
        ///
        /// # Returns
        /// `true` if verification succeeds, `false` otherwise
        pub fn is_valid_vrf_proof(
            &mut self,
            proof_bytes: Vec<u8>,
            public_key_bytes: Vec<u8>,
            input: Vec<u8>,
        ) -> bool {
            let is_valid = verify_vrf_bool(proof_bytes, public_key_bytes, input);

            if is_valid {
                self.successful_verifications += 1;
                log!("VRF verification successful (boolean check)");
            } else {
                self.failed_verifications += 1;
                log!("VRF verification failed (boolean check)");
            }

            is_valid
        }

        /// Get verification statistics
        pub fn get_stats(&self) -> (u64, u64) {
            (self.successful_verifications, self.failed_verifications)
        }

        /// Reset verification counters (for testing)
        pub fn reset_stats(&mut self) {
            self.successful_verifications = 0;
            self.failed_verifications = 0;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use near_sdk::test_utils::{accounts, VMContextBuilder};
        use near_sdk::testing_env;

        fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
            let mut builder = VMContextBuilder::new();
            builder
                .current_account_id(accounts(0))
                .signer_account_id(predecessor_account_id.clone())
                .predecessor_account_id(predecessor_account_id);
            builder
        }

        #[test]
        fn test_contract_initialization() {
            let context = get_context(accounts(1));
            testing_env!(context.build());

            let contract = VrfTestContract::new();
            let (successful, failed) = contract.get_stats();

            assert_eq!(successful, 0);
            assert_eq!(failed, 0);
        }

        #[test]
        fn test_invalid_proof_handling() {
            let context = get_context(accounts(1));
            testing_env!(context.build());

            let mut contract = VrfTestContract::new();

            // Test with invalid proof data
            let invalid_proof = vec![0u8; 80]; // All zeros - invalid proof
            let invalid_pk = vec![1u8; 32];    // Simple test key
            let input = b"test_input".to_vec();

            // Boolean check should return false for invalid proof
            let is_valid = contract.is_valid_vrf_proof(invalid_proof, invalid_pk, input);
            assert!(!is_valid);

            let (successful, failed) = contract.get_stats();
            assert_eq!(successful, 0);
            assert_eq!(failed, 1);
        }

        #[test]
        fn test_stats_reset() {
            let context = get_context(accounts(1));
            testing_env!(context.build());

            let mut contract = VrfTestContract::new();

            // Manually increment counters
            contract.failed_verifications = 5;
            contract.successful_verifications = 3;

            contract.reset_stats();

            let (successful, failed) = contract.get_stats();
            assert_eq!(successful, 0);
            assert_eq!(failed, 0);
        }
    }
}

/// Integration test that uses real VRF data from the main vrf-wasm library
#[cfg(all(test, feature = "near"))]
mod integration_tests {
    use super::near_contract_tests::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    // Import vrf-wasm for generating test data
    use vrf_wasm::vrf::ecvrf::ECVRFKeyPair;
    use vrf_wasm::vrf::{VRFKeyPair, VRFProof};
    use vrf_wasm::serde_helpers::ToFromByteArray;
    use vrf_wasm::rng;

    fn get_context(predecessor_account_id: near_sdk::AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_real_vrf_verification_in_near_contract() {
        let context = get_context(accounts(1));
        testing_env!(context.build());

        let mut contract = VrfTestContract::new();

        // Generate real VRF proof using vrf-wasm
        let mut rng_instance = rng::WasmRng;
        let keypair = ECVRFKeyPair::generate(&mut rng_instance);
        let input = b"test_input_for_near_contract";

        // Generate proof
        let proof = keypair.prove(input);
        let expected_output = proof.to_hash();

        // Extract components
        let pk_bytes = keypair.public_key().to_byte_array();
        let (gamma_bytes, challenge_bytes, scalar_bytes) = proof.to_components();

        // Construct proof bytes in expected format
        let mut proof_bytes = Vec::with_capacity(80);
        proof_bytes.extend_from_slice(&gamma_bytes);
        proof_bytes.extend_from_slice(&challenge_bytes);
        proof_bytes.extend_from_slice(&scalar_bytes);

        // Test boolean verification
        let is_valid = contract.is_valid_vrf_proof(
            proof_bytes.clone(),
            pk_bytes.to_vec(),
            input.to_vec(),
        );
        assert!(is_valid, "Real VRF proof should be valid");

        // Test full verification (this would panic on failure)
        let vrf_output = contract.verify_vrf_proof(
            proof_bytes,
            pk_bytes.to_vec(),
            input.to_vec(),
        );

        // Verify the output matches
        assert_eq!(vrf_output, expected_output, "VRF outputs should match");

        // Check stats
        let (successful, failed) = contract.get_stats();
        assert_eq!(successful, 2); // Both verifications succeeded
        assert_eq!(failed, 0);
    }
}

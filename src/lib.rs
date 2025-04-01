/*!
 * A generic implementation of Schnorr digital signatures.
 *
 * This crate provides a generic implementation of Schnorr signatures that can work with any
 * elliptic curve group that implements the `group::Group` trait. The implementation follows
 * the standard Schnorr signature scheme with the Fiat-Shamir transform to convert the
 * interactive Sigma protocol into a non-interactive digital signature.
 *
 * # Cryptographic Details
 *
 * ## Schnorr Signature Protocol
 *
 * The Schnorr signature scheme is based on the discrete logarithm problem and
 * follows this structure:
 *
 * 1. **Key Generation**:
 *    - Choose a random scalar x (private key)
 *    - Compute u = g^x (public key), where g is the group generator
 *
 * 2. **Signature Generation**:
 *    - Choose a random nonce (alpha_t)
 *    - Compute the commitment u_t = g^alpha_t
 *    - Compute challenge c = H(message || public_key || u_t) using the Fiat-Shamir transform
 *    - Compute response alpha_z = alpha_t + x·c
 *    - Output signature (c, alpha_z)
 *
 * 3. **Signature Verification**:
 *    - Compute u_t = g^alpha_z - u^c
 *    - Compute challenge c' = H(message || public_key || u_t)
 *    - Accept if c' = c
 *
 * ## Security Considerations
 *
 * - The security of Schnorr signatures relies on the discrete logarithm problem in the selected group
 * - This implementation uses a deterministic challenge derivation using the Blake3 hash function
 *
 * ## References
 *
 * - Schnorr, C. P. (1991). "Efficient Signature Generation by Smart Cards"
 * - Boneh, D., & Shoup, V. (2020). "A Graduate Course in Applied Cryptography", Chapter 19.3
 */

use group::Group;
use group::ff::Field;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use serde::{Deserialize, Serialize};

/// Public key for Schnorr signatures.
///
/// The public key contains a group element `u` which is the result of multiplying
/// the group generator by the private scalar `x` (i.e., u = g^x).
///
/// The type parameter G represents the elliptic curve group being used for signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey<G: Group> {
    /// The public key group element, computed as u = g^x where g is the group generator
    /// and x is the private key scalar.
    u: G,
}

/// Private key for Schnorr signatures.
///
/// Contains the secret scalar `x` and the corresponding public key.
///
/// The type parameter G represents the elliptic curve group being used for signatures.
#[derive(Debug, Clone)]
pub struct PrivateKey<G: Group> {
    /// The secret scalar x, which must remain confidential
    x: G::Scalar,
    /// The corresponding public key derived from x
    public: PublicKey<G>,
}

/// A Schnorr signature consisting of a challenge and response.
///
/// The signature is composed of two scalar values:
/// - `c`: The challenge derived deterministically using the Fiat-Shamir transform
/// - `alpha_z`: The response computed as alpha_t + x*c
///
/// The type parameter G represents the elliptic curve group being used for signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature<G: Group> {
    /// The challenge value derived from the hash of the message, public key, and commitment
    c: G::Scalar,
    /// The response value calculated as alpha_z = alpha_t + x·c
    alpha_z: G::Scalar,
}

// Custom serde implementation for PrivateKey
impl<G: Group> Serialize for PrivateKey<G>
where
    G::Scalar: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Only serialize the private key scalar x
        self.x.serialize(serializer)
    }
}

// Custom deserialization for PrivateKey
impl<'de, G: Group> Deserialize<'de> for PrivateKey<G>
where
    G::Scalar: Deserialize<'de>,
    G: Serialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize only the private key scalar x
        let x = G::Scalar::deserialize(deserializer)?;

        // Compute the public key from x
        let public = PublicKey {
            u: G::generator() * x,
        };

        Ok(PrivateKey { x, public })
    }
}

impl<G: Group + Serialize> PrivateKey<G> {
    /// Generates a new random private key.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A new `PrivateKey<G>` with a randomly generated scalar and derived public key
    ///
    /// # Example
    ///
    /// ```
    /// # use rand_core::OsRng;
    /// # use curve25519_dalek::RistrettoPoint;
    /// # use schnorr::PrivateKey;
    /// let private_key: PrivateKey<RistrettoPoint> = PrivateKey::random(&mut OsRng);
    /// ```
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        // Generate a random scalar for the private key
        let x = G::Scalar::random(&mut rng);

        // Compute the public key as u = g^x
        let public = PublicKey {
            u: G::generator() * x,
        };

        PrivateKey { x, public }
    }

    /// Returns a reference to the public key corresponding to this private key.
    ///
    /// # Returns
    ///
    /// A reference to the `PublicKey<G>` derived from this private key
    pub fn public(&self) -> &PublicKey<G> {
        &self.public
    }

    /// Creates a Schnorr signature for the given message.
    ///
    /// This implements the Schnorr signature algorithm with the Fiat-Shamir transform:
    /// 1. Generates a random nonce alpha_t
    /// 2. Computes the commitment u_t = g^alpha_t
    /// 3. Derives the challenge c by hashing the message, public key, and commitment
    /// 4. Computes the response alpha_z = alpha_t + x·c
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign as a byte slice
    /// * `rng` - A cryptographically secure random number generator for nonce generation
    ///
    /// # Returns
    ///
    /// A `Signature<G>` for the given message
    ///
    /// # Security Notes
    ///
    /// - The implementation uses a fresh random nonce for each signature to prevent
    ///   nonce reuse vulnerabilities
    /// - The challenge is derived deterministically using Blake3, which mitigates
    ///   issues with weak random number generators
    pub fn sign(&self, message: &[u8], mut rng: impl CryptoRngCore) -> Signature<G> {
        // Initialize the hasher with the message
        let mut hasher = blake3::Hasher::new();
        hasher.update(message);

        // Generate a random nonce and compute the commitment
        // This is the first step in the Sigma protocol (prover's commitment)
        let alpha_t = G::Scalar::random(&mut rng);
        let u_t = G::generator() * alpha_t;

        // Update the hash with public key and commitment
        // This binds the signature to this specific key and commitment
        hasher.update(
            &bincode::serde::encode_to_vec(&self.public.u, bincode::config::standard()).unwrap(),
        );
        hasher.update(&bincode::serde::encode_to_vec(&u_t, bincode::config::standard()).unwrap());

        // Use the hash output as a seed for deterministic challenge generation
        // This implements the Fiat-Shamir transform, converting interactive to non-interactive
        let mut rng = ChaCha20Rng::from_seed(*hasher.finalize().as_bytes());

        // Generate the challenge deterministically
        // This is the second step in the Sigma protocol (verifier's challenge)
        let c = G::Scalar::random(&mut rng);

        // Compute the response
        // This is the third step in the Sigma protocol (prover's response)
        // alpha_z = alpha_t + x*c
        let alpha_z = alpha_t + self.x * c;

        Signature { alpha_z, c }
    }
}

impl<G: Group + Serialize> Signature<G> {
    /// Verifies a signature against a message and public key.
    ///
    /// This method implements the Schnorr signature verification algorithm:
    /// 1. Computes u_t = g^alpha_z - u^c
    /// 2. Derives challenge c' by hashing the message, public key, and computed u_t
    /// 3. Verifies that c' equals the signature's challenge c
    ///
    /// # Arguments
    ///
    /// * `message` - The signed message as a byte slice
    /// * `public_key` - The public key to verify against
    ///
    /// # Returns
    ///
    /// A `bool` that is true if the signature is valid, and false otherwise.
    pub fn verify(&self, message: &[u8], public_key: &PublicKey<G>) -> bool {
        // Initialize the hasher with the message
        let mut hasher = blake3::Hasher::new();
        hasher.update(message);

        // Compute u_t = g^alpha_z - u^c
        // This verification equation is equivalent to checking that u_t = g^alpha_t
        // It works because:
        // g^alpha_z - u^c
        // = g^(alpha_t + x*c) - (g^x)^c
        // = g^alpha_t * g^(x*c) - g^(x*c)
        // = g^alpha_t + g^(x*c) - g^(x*c)
        // = g^alpha_t
        //
        // This is an optimization that allows verification without knowing alpha_t
        let u_t = G::generator() * self.alpha_z - public_key.u * self.c;

        // Update the hash with the public key and computed commitment
        // This must match exactly how the challenge was originally generated
        hasher.update(
            &bincode::serde::encode_to_vec(&public_key.u, bincode::config::standard()).unwrap(),
        );
        hasher.update(&bincode::serde::encode_to_vec(&u_t, bincode::config::standard()).unwrap());

        // Use the hash output as a seed for deterministic challenge regeneration
        let mut rng = ChaCha20Rng::from_seed(*hasher.finalize().as_bytes());

        // Generate the challenge deterministically - this should match the challenge
        // in the signature if the signature is valid
        let c = G::Scalar::random(&mut rng);

        &c == &self.c
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_signatures_e2e() {
        use rand_chacha::ChaCha20Rng;
        use rand_core::{OsRng, RngCore, SeedableRng};
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut rng = ChaCha20Rng::from_seed(seed);
        for _i in 0..10000 {
            use super::*;
            use curve25519_dalek::RistrettoPoint;
            let private_key: PrivateKey<RistrettoPoint> = PrivateKey::random(&mut rng);
            let mut message = [0u8; 128];
            OsRng.fill_bytes(&mut message);
            let signature = private_key.sign(&message, &mut rng);
            assert!(signature.verify(&message, private_key.public()))
        }
    }

    #[test]
    fn test_privatekey_serde() {
        use super::*;
        use bincode::config::standard;
        use curve25519_dalek::RistrettoPoint;
        use rand_core::OsRng;

        // Create a private key
        let original_key: PrivateKey<RistrettoPoint> = PrivateKey::random(&mut OsRng);

        // Serialize the private key
        let serialized = bincode::serde::encode_to_vec(&original_key, standard()).unwrap();

        // Deserialize the private key
        let deserialized: PrivateKey<RistrettoPoint> =
            bincode::serde::decode_from_slice(&serialized, standard())
                .unwrap()
                .0;

        // Verify that the deserialized key has the same components
        // The scalars should be exactly equal
        assert_eq!(
            bincode::serde::encode_to_vec(&original_key.x, standard()).unwrap(),
            bincode::serde::encode_to_vec(&deserialized.x, standard()).unwrap()
        );

        // The public keys should be exactly equal after regeneration
        assert_eq!(
            bincode::serde::encode_to_vec(&original_key.public.u, standard()).unwrap(),
            bincode::serde::encode_to_vec(&deserialized.public.u, standard()).unwrap()
        );

        // Sign a message with both keys - they should produce different signatures (due to randomness)
        // but both should verify correctly
        let message = b"test message";
        let sig1 = original_key.sign(message, &mut OsRng);
        let sig2 = deserialized.sign(message, &mut OsRng);

        assert!(sig1.verify(message, original_key.public()));
        assert!(sig2.verify(message, deserialized.public()));
    }
}

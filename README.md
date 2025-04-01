# Schnorr Signatures in Rust

This library implements Schnorr signatures, a type of digital signature scheme known for its simplicity and efficiency. The implementation is generic over any elliptic curve group and uses the Fiat-Shamir transform to convert an interactive proof into a non-interactive signature scheme.

## Background

### Sigma Protocols

Sigma protocols are a class of 3-move interactive proof systems where:
1. The prover sends a commitment (sometimes called the "announcement")
2. The verifier sends a random challenge
3. The prover sends a response that, combined with the commitment and challenge, convinces the verifier

These protocols follow a specific structure where the verifier can only respond with a challenge after seeing the prover's initial commitment, making them special cases of interactive proof systems.

Schnorr's protocol is a classic example of a sigma protocol for proving knowledge of a discrete logarithm.

**Reference:** Boneh, D., & Shoup, V. (2020). *A Graduate Course in Applied Cryptography*. Chapter 19.1-19.2 covers Sigma protocols in detail: [https://toc.cryptobook.us/](https://toc.cryptobook.us/)

### Fiat-Shamir Transform

The Fiat-Shamir transform is a technique that converts interactive proof systems (like Sigma protocols) into non-interactive ones by using a cryptographic hash function to generate the challenges. This makes it possible to implement digital signature schemes based on identification protocols.

In our implementation, we use the Blake3 hash function to generate the verifier challenge deterministically from the message and commitment, eliminating the need for interaction.

**Reference:** Fiat, A., & Shamir, A. (1986). *How to Prove Yourself: Practical Solutions to Identification and Signature Problems*. CRYPTO '86. [https://link.springer.com/chapter/10.1007/3-540-47721-7_12](https://link.springer.com/chapter/10.1007/3-540-47721-7_12)

### Schnorr Signatures

Schnorr signatures were developed by Claus-Peter Schnorr in the late 1980s. They are based on the discrete logarithm problem and offer several advantages over other signature schemes:

- Provable security (in the random oracle model)
- Simple implementation
- Short signature size
- Linear signature aggregation (multisignature capability)

Despite being patented until 2008, which limited early adoption, Schnorr signatures have gained significant attention in recent years, particularly in cryptocurrency applications like Bitcoin (which adopted Schnorr signatures via the Taproot upgrade).

**References:**
- Schnorr, C. P. (1991). *Efficient Signature Generation by Smart Cards*. Journal of Cryptology, 4(3), 161-174.
- Boneh, D., & Shoup, V. (2020). *A Graduate Course in Applied Cryptography*. Chapter 19.3 discusses the Schnorr identification protocol and signatures: [https://toc.cryptobook.us/](https://toc.cryptobook.us/)

## Implementation Details

This implementation uses:

1. **Generic Group Operations**: The code is generic over any group that implements the `group::Group` trait, allowing it to work with different elliptic curves.

2. **Constant-Time Operations**: Uses the `subtle` crate for constant-time equality checking to protect against timing attacks.

3. **Modern Hash Function**: Blake3 is used as the hash function for the Fiat-Shamir transform.

4. **Serialization**: Uses `bincode` and `serde` for serializing group elements when computing hashes.

Key components of the implementation:

- `PublicKey<G>`: Holds the public verification key (u = g^x)
- `PrivateKey<G>`: Contains the secret key x and the corresponding public key
- `Signature<G>`: Holds the challenge c and the response alpha_z

The signature generation and verification algorithms follow the standard Schnorr signature scheme with Fiat-Shamir:

1. **Key Generation**: Choose a random scalar x and compute u = g^x
2. **Signing**:
   - Choose a random nonce alpha_t
   - Compute the commitment u_t = g^alpha_t
   - Derive challenge c by hashing the message, public key, and commitment
   - Compute the response alpha_z = alpha_t + x·c
   - Output signature (c, alpha_z)
3. **Verification**:
   - Compute u_t = g^alpha_z - u^c
   - Derive challenge c' by hashing the message, public key, and computed u_t
   - Accept if c' = c

**Reference for security analysis:** Pointcheval, D., & Stern, J. (2000). *Security Arguments for Digital Signatures and Blind Signatures*. Journal of Cryptology, 13(3), 361-396.

## Usage

The library can be used with any curve that implements the `group::Group` trait. The tests show an example using Ristretto points from the `curve25519-dalek` library.

```rust
use rand_core::OsRng;
use curve25519_dalek::RistrettoPoint;
use schnorr::PrivateKey;

// Generate a key pair
let private_key: PrivateKey<RistrettoPoint> = PrivateKey::random(&mut OsRng);
let public_key = private_key.public();

// Sign a message
let message = b"Hello, world!";
let signature = private_key.sign(message, &mut OsRng);

// Verify the signature
assert!(signature.verify(message, public_key));
```

## Security Considerations

1. **Nonce Reuse**: Never reuse the same nonce (alpha_t) for different messages, as this would reveal the private key.

2. **Random Number Generation**: The implementation uses ChaCha20Rng for deterministic derivation of challenges, but requires a secure RNG for key generation and nonce selection.

**Reference:** Pornin, T. (2013). *Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)*. RFC 6979. [https://datatracker.ietf.org/doc/html/rfc6979](https://datatracker.ietf.org/doc/html/rfc6979)

# Cryptographic Concepts in goobs-encryption

This document provides an overview of the cryptographic concepts and algorithms used in the goobs-encryption library. Understanding these concepts is crucial for using the library effectively and securely.

## Table of Contents

1. [Symmetric Encryption](#symmetric-encryption)
2. [AES (Advanced Encryption Standard)](#aes-advanced-encryption-standard)
3. [GCM (Galois/Counter Mode)](#gcm-galoiscounter-mode)
4. [Key Derivation](#key-derivation)
5. [PBKDF2 (Password-Based Key Derivation Function 2)](#pbkdf2-password-based-key-derivation-function-2)
6. [Initialization Vector (IV)](#initialization-vector-iv)
7. [Salt](#salt)
8. [Authentication Tag](#authentication-tag)
9. [Key Rotation](#key-rotation)

## Symmetric Encryption

Symmetric encryption uses the same key for both encryption and decryption. It's fast and efficient for large amounts of data, but requires secure key exchange between parties.

In goobs-encryption: We use symmetric encryption (AES) for its speed and efficiency.

## AES (Advanced Encryption Standard)

AES is a widely-used symmetric encryption algorithm. It operates on fixed-size blocks of data (128 bits) and supports key sizes of 128, 192, or 256 bits.

In goobs-encryption: We use AES with a 256-bit key for maximum security.

## GCM (Galois/Counter Mode)

GCM is an mode of operation for symmetric block ciphers. It provides both confidentiality and authenticity (integrity) of the data.

Key features:

- Allows for authentication of additional, non-encrypted data (AAD)
- Produces an authentication tag to verify the integrity of the data
- Highly efficient and suitable for high-speed implementations

In goobs-encryption: We use AES-GCM, which combines AES encryption with the GCM mode of operation.

## Key Derivation

Key derivation is the process of generating one or more secret keys from a master secret (often a password or passphrase).

In goobs-encryption: We use key derivation to generate a secure encryption key from the user-provided password.

## PBKDF2 (Password-Based Key Derivation Function 2)

PBKDF2 is a key derivation function that applies a pseudorandom function (like a hash function) to the input password along with a salt value, and repeats the process multiple times to produce a derived key.

Key features:

- Uses a salt to protect against rainbow table attacks
- Configurable iteration count to increase computational cost and resist brute-force attacks

In goobs-encryption: We use PBKDF2 with SHA-256 as the underlying hash function to derive the encryption key from the provided password.

## Initialization Vector (IV)

An IV is a fixed-size input to a cryptographic primitive. It's typically required to be random or pseudorandom and unique for each encryption operation.

Purpose:

- Ensures that encrypting the same plaintext multiple times produces different ciphertexts
- Prevents attackers from detecting patterns in encrypted data

In goobs-encryption: We generate a new random IV for each encryption operation.

## Salt

A salt is random data used as an additional input to a one-way function that hashes data, a password, or a passphrase.

Purpose:

- Defends against dictionary attacks and pre-computed rainbow table attacks
- Adds randomness to the input, increasing the complexity of cracking the derived key

In goobs-encryption: We use a unique salt for each encryption operation when deriving the key using PBKDF2.

## Authentication Tag

An authentication tag is a fixed-size piece of information used to authenticate the source of a message and/or its contents.

Purpose:

- Ensures the integrity and authenticity of the encrypted data
- Allows the receiver to detect any changes to the ciphertext

In goobs-encryption: GCM mode produces an authentication tag, which we include with the encrypted data.

## Key Rotation

Key rotation is the practice of regularly changing cryptographic keys to limit the amount of data encrypted with a single key.

Benefits:

- Limits the impact of a compromised key
- Helps maintain the long-term security of encrypted data

In goobs-encryption: We provide automatic key rotation based on configurable time intervals.

---

Understanding these concepts will help you make informed decisions when using goobs-encryption and ensure that you're implementing encryption in your application securely. Remember, while goobs-encryption aims to simplify the process of encryption, it's crucial to have a good grasp of these underlying principles when dealing with sensitive data.

/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Init
public import Cslib.Crypto.Foundations.Negligible
public import Cslib.Crypto.Foundations.Advantage

@[expose] public section

/-!
# CSLib Cryptography Library

Formalization of cryptographic definitions and theorems from
*A Graduate Course in Applied Cryptography* by Dan Boneh and Victor Shoup (Version 0.6, 2023).

The library is organized into three main parts, following the structure of the book:

## Part I: Secret Key Cryptography (Chapters 2–9)

- `Cslib.Crypto.SecretKey.Encryption`: Shannon ciphers, computational ciphers, semantic security
- `Cslib.Crypto.SecretKey.StreamCipher`: Pseudo-random generators, stream ciphers
- `Cslib.Crypto.SecretKey.BlockCipher`: Block ciphers, pseudo-random functions
- `Cslib.Crypto.SecretKey.CPA`: Chosen plaintext attack security
- `Cslib.Crypto.SecretKey.MAC`: Message authentication codes
- `Cslib.Crypto.SecretKey.UHF`: Universal hash functions
- `Cslib.Crypto.SecretKey.CRH`: Collision resistant hashing
- `Cslib.Crypto.SecretKey.AE`: Authenticated encryption

## Part II: Public Key Cryptography (Chapters 10–17)

- `Cslib.Crypto.PublicKey`: Trapdoor functions, Diffie-Hellman, public key encryption, signatures,
  elliptic curves, lattice-based cryptography

## Part III: Protocols (Chapters 18–23)

- `Cslib.Crypto.Protocols`: Identification, zero-knowledge proofs, key exchange, threshold
  cryptography, secure multi-party computation

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023]
-/

namespace Cslib.Crypto

end Cslib.Crypto

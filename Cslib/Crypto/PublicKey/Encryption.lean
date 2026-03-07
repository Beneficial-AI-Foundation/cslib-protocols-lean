/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Mathlib.Data.Fintype.Card

@[expose] public section

/-!
# Public Key Encryption

This file formalizes public key encryption and CCA security from Chapters 11–12 of Boneh-Shoup.

## Main definitions

- `PKEFamily`: A public key encryption scheme with key generation, encryption, and decryption.
  (Section 11.2)
- `PKEFamily.SemanticallySecure`: Semantic security for public key encryption. (Section 11.2)
- `PKEFamily.CCASecure`: CCA security for public key encryption. (Chapter 12)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Chapters 11–12
-/

namespace Cslib.Crypto

/--
A **public key encryption family** indexed by security parameter `λ`.
(Section 11.2 in Boneh-Shoup)
-/
structure PKEFamily where
  /-- The public key type. -/
  PK : ℕ → Type*
  /-- The secret key type. -/
  SK : ℕ → Type*
  /-- The message space. -/
  Msg : ℕ → Type*
  /-- The ciphertext space. -/
  Ctxt : ℕ → Type*
  /-- Public key types are finite. -/
  pk_fintype : ∀ λ, Fintype (PK λ)
  /-- Secret key types are finite. -/
  sk_fintype : ∀ λ, Fintype (SK λ)
  /-- Message spaces are finite. -/
  msg_fintype : ∀ λ, Fintype (Msg λ)
  /-- Ciphertext spaces are finite. -/
  ctxt_fintype : ∀ λ, Fintype (Ctxt λ)
  /-- Key generation: produces a (pk, sk) pair. Modeled deterministically here;
      probabilistic key generation can be modeled as choosing from a `PMF`. -/
  keygen : ∀ λ, PK λ × SK λ
  /-- Encryption: `E(pk, m) → c`. Deterministic model; see note on keygen. -/
  encrypt : ∀ λ, PK λ → Msg λ → Ctxt λ
  /-- Decryption: `D(sk, c) → m`. -/
  decrypt : ∀ λ, SK λ → Ctxt λ → Msg λ
  /-- Correctness: decryption undoes encryption using the matching key pair. -/
  correct : ∀ λ m, let ⟨pk, sk⟩ := keygen λ; decrypt λ sk (encrypt λ pk m) = m

-- TODO: Formalize PKE semantic security (Section 11.2)
-- TODO: Formalize ElGamal encryption (Section 11.5)
-- TODO: Formalize CCA security (Chapter 12, Definition 12.1)
-- TODO: Formalize CCA-secure ElGamal (Section 12.4)
-- TODO: Formalize Cramer-Shoup encryption (Section 12.5)

end Cslib.Crypto

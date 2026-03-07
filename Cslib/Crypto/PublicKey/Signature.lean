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
# Digital Signatures

This file formalizes digital signature schemes from Chapters 13–14 of Boneh-Shoup.

## Main definitions

- `SignatureFamily`: A digital signature scheme with key generation, signing, and verification.
  (Section 13.1)
- `SignatureFamily.EUFCMASecure`: Existential unforgeability under chosen message attack.
  (Section 13.1.1)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Chapters 13–14
-/

namespace Cslib.Crypto

/--
A **digital signature family** indexed by security parameter `λ`.
(Section 13.1 in Boneh-Shoup)
-/
structure SignatureFamily where
  /-- The public (verification) key type. -/
  VK : ℕ → Type*
  /-- The secret (signing) key type. -/
  SK : ℕ → Type*
  /-- The message space. -/
  Msg : ℕ → Type*
  /-- The signature space. -/
  Sig : ℕ → Type*
  /-- Verification key types are finite. -/
  vk_fintype : ∀ sp, Fintype (VK sp)
  /-- Signing key types are finite. -/
  sk_fintype : ∀ sp, Fintype (SK sp)
  /-- Message spaces are finite. -/
  msg_fintype : ∀ sp, Fintype (Msg sp)
  /-- Signature spaces are finite. -/
  sig_fintype : ∀ sp, Fintype (Sig sp)
  /-- Key generation: produces a (vk, sk) pair. -/
  keygen : ∀ sp, VK sp × SK sp
  /-- Signing: `Sign(sk, m) → σ`. -/
  sign : ∀ sp, SK sp → Msg sp → Sig sp
  /-- Verification: `Verify(vk, m, σ) → {accept, reject}`. -/
  verify : ∀ sp, VK sp → Msg sp → Sig sp → Bool
  /-- Correctness: honestly generated signatures always verify. -/
  correct : ∀ sp m, let ⟨vk, sk⟩ := keygen sp; verify sp vk m (sign sp sk m) = true

-- TODO: Formalize EUF-CMA security (Section 13.1.1)
-- TODO: Formalize full domain hash signatures (Section 13.3)
-- TODO: Formalize Lamport signatures (Section 14.1)
-- TODO: Formalize Merkle signature trees (Section 14.6)

end Cslib.Crypto

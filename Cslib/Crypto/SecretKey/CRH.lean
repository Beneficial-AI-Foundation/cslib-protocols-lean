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
# Collision Resistant Hashing

This file formalizes collision resistant hash functions from Chapter 8 of Boneh-Shoup.

## Main definitions

- `CRHFamily`: A family of hash functions `H : Key → Msg → Digest` that is collision
  resistant: no efficient adversary can find `m₀ ≠ m₁` with `H(k, m₀) = H(k, m₁)`.
  (Section 8.1)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 8
-/

namespace Cslib.Crypto

/--
A **collision resistant hash function family** indexed by security parameter `λ`.
(Section 8.1 in Boneh-Shoup)
-/
structure CRHFamily where
  /-- The key space (public hash key). -/
  Key : ℕ → Type*
  /-- The message space (domain). -/
  Msg : ℕ → Type*
  /-- The digest space (range), which must be smaller than the message space. -/
  Digest : ℕ → Type*
  /-- Key spaces are finite. -/
  key_fintype : ∀ λ, Fintype (Key λ)
  /-- Message spaces are finite. -/
  msg_fintype : ∀ λ, Fintype (Msg λ)
  /-- Digest spaces are finite. -/
  digest_fintype : ∀ λ, Fintype (Digest λ)
  /-- Key spaces are nonempty. -/
  key_nonempty : ∀ λ, Nonempty (Key λ)
  /-- The hash function `H(k, m) → d`. -/
  hash : ∀ λ, Key λ → Msg λ → Digest λ
  /-- The hash is compressing: digest space is smaller than message space. -/
  compressing : ∀ λ, Fintype.card (Digest λ) < Fintype.card (Msg λ)

attribute [instance] CRHFamily.key_fintype CRHFamily.msg_fintype
  CRHFamily.digest_fintype CRHFamily.key_nonempty

-- TODO: Formalize collision resistance security game (Section 8.1)
-- TODO: Formalize birthday attack bound (Section 8.3)
-- TODO: Formalize Merkle-Damgård paradigm (Section 8.4)
-- TODO: Formalize Davies-Meyer compression (Section 8.5)
-- TODO: Formalize HMAC (Section 8.7)
-- TODO: Formalize sponge construction (Section 8.8)
-- TODO: Formalize Merkle trees (Section 8.9)
-- TODO: Formalize random oracle model (Section 8.10)

end Cslib.Crypto

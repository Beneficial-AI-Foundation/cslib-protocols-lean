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
# Message Authentication Codes

This file formalizes MACs from Chapter 6 of Boneh-Shoup.

## Main definitions

- `MACFamily`: A family of MACs indexed by security parameter, consisting of a signing
  algorithm `S(k, m)` and a verification algorithm `V(k, m, t)`. (Section 6.1)

- `MACFamily.Secure`: A MAC is secure if no efficient adversary can produce an existential
  forgery. (Section 6.1)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 6
-/

namespace Cslib.Crypto

/--
A **MAC (Message Authentication Code) family** indexed by security parameter `λ`.
(Section 6.1 in Boneh-Shoup)
-/
structure MACFamily where
  /-- The key space. -/
  Key : ℕ → Type*
  /-- The message space. -/
  Msg : ℕ → Type*
  /-- The tag space. -/
  Tag : ℕ → Type*
  /-- Key spaces are finite. -/
  key_fintype : ∀ λ, Fintype (Key λ)
  /-- Message spaces are finite. -/
  msg_fintype : ∀ λ, Fintype (Msg λ)
  /-- Tag spaces are finite. -/
  tag_fintype : ∀ λ, Fintype (Tag λ)
  /-- Key spaces are nonempty. -/
  key_nonempty : ∀ λ, Nonempty (Key λ)
  /-- The signing algorithm `S(k, m) → t`. -/
  sign : ∀ λ, Key λ → Msg λ → Tag λ
  /-- The verification algorithm `V(k, m, t) → {accept, reject}`. -/
  verify : ∀ λ, Key λ → Msg λ → Tag λ → Bool
  /-- Correctness: honestly generated tags always verify. -/
  correct : ∀ λ k m, verify λ k m (sign λ k m) = true

attribute [instance] MACFamily.key_fintype MACFamily.msg_fintype
  MACFamily.tag_fintype MACFamily.key_nonempty

-- TODO: Formalize MAC security (existential forgery game)
-- TODO: Formalize PRF-based MACs (Section 6.3)
-- TODO: Formalize CBC-MAC (Section 6.4)
-- TODO: Formalize CMAC (Section 6.7)
-- TODO: Formalize PMAC (Section 6.11)

end Cslib.Crypto

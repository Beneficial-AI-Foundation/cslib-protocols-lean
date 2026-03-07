/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Mathlib.Data.Fintype.Card
public import Mathlib.Probability.ProbabilityMassFunction.Basic

@[expose] public section

/-!
# Computational Ciphers

This file formalizes computational ciphers (Section 2.2.1) and the formal asymptotic framework
(Section 2.3.2) from Boneh-Shoup.

A computational cipher generalizes a Shannon cipher by allowing the encryption algorithm to
be probabilistic and by parameterizing everything by a security parameter `λ`.

## Main definitions

- `Cipher`: A (deterministic) computational cipher `E = (E, D)` defined over `(K, M, C)`,
  where `K`, `M`, `C` are types (which may depend on a security parameter). Encryption is
  deterministic with correctness `D(k, E(k, m)) = m`. (Section 2.2.1, simplified)

- `CipherFamily`: A family of ciphers indexed by a security parameter `λ : ℕ`, capturing the
  asymptotic framework of Definition 2.10.

## Discussion

In the simplified treatment (Section 2.2.1), a cipher is defined over fixed finite sets `(K, M, C)`
with `E : K → M → C` (possibly probabilistic) and `D : K → C → M` (deterministic), satisfying
correctness. In the formal treatment (Section 2.3.2, Definition 2.10), these become families
indexed by security parameter `λ` and system parameter `Λ`.

We formalize both levels: `Cipher` for the simplified single-instance view, and `CipherFamily`
for the asymptotic parameterized view.

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Sections 2.2.1, 2.3.2
-/

namespace Cslib.Crypto

/--
A (deterministic) **cipher** defined over types `Key`, `Msg`, `Ctxt`. This is the simplified
formulation from Section 2.2.1, without security/system parameters.

Note: A deterministic cipher is also a `ShannonCipher`. Probabilistic ciphers will be modeled
separately using `PMF` for the encryption output.
-/
abbrev Cipher (Key Msg Ctxt : Type*) := ShannonCipher Key Msg Ctxt

/--
A **cipher family** indexed by a security parameter `λ : ℕ`, formalizing Definition 2.10
in Boneh-Shoup. For each value of `λ`, we get finite types for keys, messages, and ciphertexts,
along with encryption and decryption algorithms satisfying correctness.
-/
structure CipherFamily where
  /-- The key space for security parameter `λ`. -/
  Key : ℕ → Type*
  /-- The message space for security parameter `λ`. -/
  Msg : ℕ → Type*
  /-- The ciphertext space for security parameter `λ`. -/
  Ctxt : ℕ → Type*
  /-- Key spaces are finite. -/
  key_fintype : ∀ λ, Fintype (Key λ)
  /-- Message spaces are finite. -/
  msg_fintype : ∀ λ, Fintype (Msg λ)
  /-- Ciphertext spaces are finite. -/
  ctxt_fintype : ∀ λ, Fintype (Ctxt λ)
  /-- Key spaces are nonempty (we can always sample a key). -/
  key_nonempty : ∀ λ, Nonempty (Key λ)
  /-- The encryption algorithm. -/
  encrypt : ∀ λ, Key λ → Msg λ → Ctxt λ
  /-- The decryption algorithm. -/
  decrypt : ∀ λ, Key λ → Ctxt λ → Msg λ
  /-- Correctness: for all `λ`, `k`, `m`, `D(k, E(k, m)) = m`. -/
  correct : ∀ λ k m, decrypt λ k (encrypt λ k m) = m

attribute [instance] CipherFamily.key_fintype CipherFamily.msg_fintype
  CipherFamily.ctxt_fintype CipherFamily.key_nonempty

/--
Extract a single cipher instance from a cipher family at a given security parameter.
-/
def CipherFamily.at (E : CipherFamily) (λ : ℕ) : Cipher (E.Key λ) (E.Msg λ) (E.Ctxt λ) where
  encrypt := E.encrypt λ
  decrypt := E.decrypt λ
  correct := E.correct λ

end Cslib.Crypto

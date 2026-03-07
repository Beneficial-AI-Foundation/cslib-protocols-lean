/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Mathlib.Data.Fintype.Card
public import Mathlib.GroupTheory.Perm.Basic

@[expose] public section

/-!
# Block Ciphers

This file formalizes block ciphers from Chapter 4, Section 4.1 of Boneh-Shoup.

A block cipher is a cipher where the message and ciphertext spaces are the same (the "block
space") and for each key, encryption is a permutation on the block space.

## Main definitions

- `BlockCipherFamily`: A family of block ciphers indexed by security parameter `λ`, where
  for each key, encryption defines a permutation on the block space. (Section 4.1)

- `BlockCipherFamily.Secure`: A block cipher is secure if no efficient adversary can
  distinguish encryptions under a random key from a truly random permutation.

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Section 4.1
-/

namespace Cslib.Crypto

/--
A **block cipher family** indexed by security parameter `λ`. For each `λ` and each key `k`,
encryption `E(k, ·)` is a permutation on the block space `X`.
(Section 4.1 in Boneh-Shoup)
-/
structure BlockCipherFamily where
  /-- The key space for security parameter `λ`. -/
  Key : ℕ → Type*
  /-- The block space (= message space = ciphertext space) for security parameter `λ`. -/
  Block : ℕ → Type*
  /-- Key spaces are finite. -/
  key_fintype : ∀ λ, Fintype (Key λ)
  /-- Block spaces are finite. -/
  block_fintype : ∀ λ, Fintype (Block λ)
  /-- Key spaces are nonempty. -/
  key_nonempty : ∀ λ, Nonempty (Key λ)
  /-- Block spaces are nonempty. -/
  block_nonempty : ∀ λ, Nonempty (Block λ)
  /-- For each key, encryption is a permutation on the block space.
      We use Mathlib's `Equiv.Perm` to represent this. -/
  perm : ∀ λ, Key λ → Equiv.Perm (Block λ)

attribute [instance] BlockCipherFamily.key_fintype BlockCipherFamily.block_fintype
  BlockCipherFamily.key_nonempty BlockCipherFamily.block_nonempty

/--
Extract the encryption function from a block cipher.
-/
def BlockCipherFamily.encrypt (E : BlockCipherFamily) (λ : ℕ) (k : E.Key λ) (x : E.Block λ) :
    E.Block λ :=
  E.perm λ k x

/--
Extract the decryption function from a block cipher.
-/
def BlockCipherFamily.decrypt (E : BlockCipherFamily) (λ : ℕ) (k : E.Key λ) (y : E.Block λ) :
    E.Block λ :=
  (E.perm λ k).symm y

/--
Block cipher correctness: decryption inverts encryption.
-/
theorem BlockCipherFamily.correct (E : BlockCipherFamily) (λ : ℕ) (k : E.Key λ)
    (x : E.Block λ) : E.decrypt λ k (E.encrypt λ k x) = x :=
  (E.perm λ k).symm_apply_apply x

/--
Convert a `BlockCipherFamily` to a `CipherFamily`.
-/
def BlockCipherFamily.toCipherFamily (E : BlockCipherFamily) : CipherFamily where
  Key := E.Key
  Msg := E.Block
  Ctxt := E.Block
  key_fintype := E.key_fintype
  msg_fintype := E.block_fintype
  ctxt_fintype := E.block_fintype
  key_nonempty := E.key_nonempty
  encrypt λ k m := E.encrypt λ k m
  decrypt λ k c := E.decrypt λ k c
  correct λ k m := E.correct λ k m

/--
A **block cipher adversary** (for the security game of Section 4.1) receives oracle access
to either (1) `E(k, ·)` for a random key `k`, or (2) a truly random permutation `π`,
and must distinguish the two cases.
-/
structure BCAdversary (E : BlockCipherFamily) where
  /-- Given oracle access (modeled as a permutation), output a guess bit. -/
  distinguish : ∀ λ, Equiv.Perm (E.Block λ) → Bool

/--
The **block cipher advantage** of adversary `A` against block cipher `E`:

`BCadv[A, E](λ) := |Pr[A(E(k,·)) = 1] - Pr[A(π) = 1]|`

where `k ←$ K` and `π ←$ Perms(X)`.
-/
noncomputable def BCAdvantage (E : BlockCipherFamily) (A : BCAdversary E) (λ : ℕ) : ℝ :=
  let prReal :=
    (Finset.univ.filter fun (k : E.Key λ) =>
      A.distinguish λ (E.perm λ k) = true).card / (Fintype.card (E.Key λ) : ℝ)
  let prIdeal :=
    (Finset.univ.filter fun (π : Equiv.Perm (E.Block λ)) =>
      A.distinguish λ π = true).card / (Fintype.card (Equiv.Perm (E.Block λ)) : ℝ)
  Advantage prReal prIdeal

/--
A block cipher family is **secure** if the block cipher advantage is negligible for
all adversaries.
(Section 4.1 in Boneh-Shoup)
-/
def BlockCipherFamily.Secure (E : BlockCipherFamily) : Prop :=
  ∀ A : BCAdversary E, Negligible (fun λ => BCAdvantage E A λ)

end Cslib.Crypto

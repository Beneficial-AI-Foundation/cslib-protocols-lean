/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.SecretKey.Encryption.ComputationalCipher
public import Mathlib.GroupTheory.Perm.Basic
public import Mathlib.Data.Fintype.Perm

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
  key_fintype : ∀ sp, Fintype (Key sp)
  /-- Block spaces are finite. -/
  block_fintype : ∀ sp, Fintype (Block sp)
  /-- Key spaces are nonempty. -/
  key_nonempty : ∀ sp, Nonempty (Key sp)
  /-- Block spaces are nonempty. -/
  block_nonempty : ∀ sp, Nonempty (Block sp)
  /-- Block spaces have decidable equality. -/
  block_deceq : ∀ sp, DecidableEq (Block sp)
  /-- For each key, encryption is a permutation on the block space.
      We use Mathlib's `Equiv.Perm` to represent this. -/
  perm : ∀ sp, Key sp → Equiv.Perm (Block sp)

attribute [instance] BlockCipherFamily.key_fintype BlockCipherFamily.block_fintype
  BlockCipherFamily.key_nonempty BlockCipherFamily.block_nonempty BlockCipherFamily.block_deceq

/--
Extract the encryption function from a block cipher.
-/
def BlockCipherFamily.encrypt (E : BlockCipherFamily) (sp : ℕ) (k : E.Key sp) (x : E.Block sp) :
    E.Block sp :=
  E.perm sp k x

/--
Extract the decryption function from a block cipher.
-/
def BlockCipherFamily.decrypt (E : BlockCipherFamily) (sp : ℕ) (k : E.Key sp) (y : E.Block sp) :
    E.Block sp :=
  (E.perm sp k).symm y

/--
Block cipher correctness: decryption inverts encryption.
-/
theorem BlockCipherFamily.correct (E : BlockCipherFamily) (sp : ℕ) (k : E.Key sp)
    (x : E.Block sp) : E.decrypt sp k (E.encrypt sp k x) = x :=
  (E.perm sp k).symm_apply_apply x

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
  encrypt sp k m := E.encrypt sp k m
  decrypt sp k c := E.decrypt sp k c
  correct sp k m := E.correct sp k m

/--
A **block cipher adversary** (for the security game of Section 4.1) receives oracle access
to either (1) `E(k, ·)` for a random key `k`, or (2) a truly random permutation `π`,
and must distinguish the two cases.
-/
structure BCAdversary (E : BlockCipherFamily) where
  /-- Given oracle access (modeled as a permutation), output a guess bit. -/
  distinguish : ∀ sp, Equiv.Perm (E.Block sp) → Bool

/--
The **block cipher advantage** of adversary `A` against block cipher `E`:

`BCadv[A, E](λ) := |Pr[A(E(k,·)) = 1] - Pr[A(π) = 1]|`

where `k ←$ K` and `π ←$ Perms(X)`.
-/
noncomputable def BCAdvantage (E : BlockCipherFamily) (A : BCAdversary E) (sp : ℕ) : ℝ :=
  let prReal :=
    (Finset.univ.filter fun (k : E.Key sp) =>
      A.distinguish sp (E.perm sp k) = true).card / (Fintype.card (E.Key sp) : ℝ)
  let prIdeal :=
    (Finset.univ.filter fun (π : Equiv.Perm (E.Block sp)) =>
      A.distinguish sp π = true).card / (Fintype.card (Equiv.Perm (E.Block sp)) : ℝ)
  Advantage prReal prIdeal

/--
A block cipher family is **secure** if the block cipher advantage is negligible for
all adversaries.
(Section 4.1 in Boneh-Shoup)
-/
def BlockCipherFamily.Secure (E : BlockCipherFamily) : Prop :=
  ∀ A : BCAdversary E, Negligible (fun sp => BCAdvantage E A sp)

end Cslib.Crypto

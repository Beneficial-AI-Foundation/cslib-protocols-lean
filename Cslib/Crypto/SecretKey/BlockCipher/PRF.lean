/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.SecretKey.BlockCipher.Basic
public import Mathlib.Data.Fintype.Pi

@[expose] public section

/-!
# Pseudo-Random Functions

This file formalizes pseudo-random functions (PRFs) from Chapter 4, Section 4.4 of Boneh-Shoup.

## Main definitions

- `PRFFamily`: A family of PRFs indexed by security parameter `λ`, consisting of a keyed
  function `F : Key → Domain → Range`. (Section 4.4.1)

- `PRFFamily.Secure`: A PRF is secure if no efficient adversary with oracle access can
  distinguish `F(k, ·)` for random `k` from a truly random function.

## Main statements

- `BlockCipherFamily.toSecurePRF`: A secure block cipher is also a secure PRF, provided
  the block space is super-poly in size. (Corollary to Theorem 4.4 / Section 4.4.3)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Section 4.4
-/

namespace Cslib.Crypto

/--
A **pseudo-random function (PRF) family** indexed by security parameter `λ`.
A PRF maps keys and domain elements to range elements via `eval`.
(Section 4.4.1 in Boneh-Shoup)
-/
structure PRFFamily where
  /-- The key space for security parameter `λ`. -/
  Key : ℕ → Type*
  /-- The domain (input space) for security parameter `λ`. -/
  Domain : ℕ → Type*
  /-- The range (output space) for security parameter `λ`. -/
  Range : ℕ → Type*
  /-- Key spaces are finite. -/
  key_fintype : ∀ sp, Fintype (Key sp)
  /-- Domain spaces are finite. -/
  domain_fintype : ∀ sp, Fintype (Domain sp)
  /-- Range spaces are finite. -/
  range_fintype : ∀ sp, Fintype (Range sp)
  /-- Domain spaces have decidable equality. -/
  domain_deceq : ∀ sp, DecidableEq (Domain sp)
  /-- Key spaces are nonempty. -/
  key_nonempty : ∀ sp, Nonempty (Key sp)
  /-- The PRF evaluation function `F(k, x)`. -/
  eval : ∀ sp, Key sp → Domain sp → Range sp

attribute [instance] PRFFamily.key_fintype PRFFamily.domain_fintype
  PRFFamily.range_fintype PRFFamily.key_nonempty PRFFamily.domain_deceq

/--
A **PRF adversary** gets oracle access to either `F(k, ·)` for random `k` or a truly random
function `f : Domain → Range`, and must distinguish the two cases.

We model the adversary as receiving the function and outputting a bit.
-/
structure PRFAdversary (F : PRFFamily) where
  /-- Given oracle access (modeled as a function), output a guess bit. -/
  distinguish : ∀ sp, (F.Domain sp → F.Range sp) → Bool

/--
The **PRF advantage** of adversary `A` against PRF `F`:

`PRFadv[A, F](λ) := |Pr[A^{F(k,·)} = 1] - Pr[A^{f} = 1]|`

where `k ←$ Key` and `f ←$ Funs(Domain, Range)`.
-/
noncomputable def PRFAdvantage (F : PRFFamily) (A : PRFAdversary F) (sp : ℕ) : ℝ :=
  let prReal :=
    (Finset.univ.filter fun (k : F.Key sp) =>
      A.distinguish sp (F.eval sp k) = true).card / (Fintype.card (F.Key sp) : ℝ)
  let prIdeal :=
    (Finset.univ.filter fun (f : F.Domain sp → F.Range sp) =>
      A.distinguish sp f = true).card / (Fintype.card (F.Domain sp → F.Range sp) : ℝ)
  Advantage prReal prIdeal

/--
A PRF family is **secure** if the PRF advantage is negligible for all adversaries.
(Section 4.4.1 in Boneh-Shoup)
-/
def PRFFamily.Secure (F : PRFFamily) : Prop :=
  ∀ A : PRFAdversary F, Negligible (fun sp => PRFAdvantage F A sp)

/--
Convert a block cipher family to a PRF family (since a block cipher `E(k, ·)` is in particular
a function from the block space to itself).
-/
def BlockCipherFamily.toPRFFamily (E : BlockCipherFamily) : PRFFamily where
  Key := E.Key
  Domain := E.Block
  Range := E.Block
  key_fintype := E.key_fintype
  domain_fintype := E.block_fintype
  range_fintype := E.block_fintype
  domain_deceq := E.block_deceq
  key_nonempty := E.key_nonempty
  eval sp k x := E.perm sp k x

end Cslib.Crypto

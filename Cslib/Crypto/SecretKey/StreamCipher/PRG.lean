/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.SecretKey.Encryption.ShannonCipher
public import Mathlib.Data.Fintype.Card

@[expose] public section

/-!
# Pseudo-Random Generators

This file formalizes pseudo-random generators (PRGs) and stream ciphers from Chapter 3
of Boneh-Shoup.

## Main definitions

- `PRG`: A pseudo-random generator mapping seeds of type `Seed` to outputs of type `Output`,
  where `|Output| > |Seed|` (the output is longer than the seed). (Definition 3.1)

- `PRG.Secure`: A PRG is secure if no efficient adversary can distinguish the output of
  `G(s)` for random `s` from a truly random element of the output space.

- `StreamCipher`: A stream cipher built from a PRG: `E(k, m) = G(k) ⊕ m`. (Section 3.2)

## Main statements

- `StreamCipher.semanticallysecure_of_secure_prg`: If `G` is a secure PRG, then the
  stream cipher built from `G` is semantically secure. (Theorem 3.1)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Sections 3.1–3.2
-/

namespace Cslib.Crypto

/--
A **pseudo-random generator** (PRG) family indexed by security parameter `λ`.
A PRG maps a short seed to a longer output.
(Definition 3.1 in Boneh-Shoup)
-/
structure PRGFamily where
  /-- The seed space for security parameter `λ`. -/
  Seed : ℕ → Type*
  /-- The output space for security parameter `λ`. -/
  Output : ℕ → Type*
  /-- Seed spaces are finite. -/
  seed_fintype : ∀ sp, Fintype (Seed sp)
  /-- Output spaces are finite. -/
  output_fintype : ∀ sp, Fintype (Output sp)
  /-- Seed spaces are nonempty. -/
  seed_nonempty : ∀ sp, Nonempty (Seed sp)
  /-- Output spaces are nonempty. -/
  output_nonempty : ∀ sp, Nonempty (Output sp)
  /-- The generator function `G : Seed → Output`. -/
  generate : ∀ sp, Seed sp → Output sp
  /-- The output is strictly longer than the seed (expansion). -/
  expansion : ∀ sp, Fintype.card (Seed sp) < Fintype.card (Output sp)

attribute [instance] PRGFamily.seed_fintype PRGFamily.output_fintype
  PRGFamily.seed_nonempty PRGFamily.output_nonempty

/--
A **PRG adversary** (also called a statistical test or distinguisher) is an algorithm that
takes an element of the output space and outputs a bit.
-/
structure PRGAdversary (G : PRGFamily) where
  /-- Given an element of the output space, output `true` or `false`. -/
  distinguish : ∀ sp, G.Output sp → Bool

/--
The **PRG advantage** of adversary `A` against PRG `G` at security parameter `λ`:

`PRGadv[A, G](λ) := |Pr[A(G(s)) = 1] - Pr[A(r) = 1]|`

where `s ←$ Seed` and `r ←$ Output`.
(Attack Game 3.1 in Boneh-Shoup)
-/
noncomputable def PRGAdvantage
    (G : PRGFamily) (A : PRGAdversary G) (sp : ℕ) : ℝ :=
  let prReal :=
    (Finset.univ.filter fun (s : G.Seed sp) =>
      A.distinguish sp (G.generate sp s) = true).card / (Fintype.card (G.Seed sp) : ℝ)
  let prRandom :=
    (Finset.univ.filter fun (r : G.Output sp) =>
      A.distinguish sp r = true).card / (Fintype.card (G.Output sp) : ℝ)
  Advantage prReal prRandom

/--
A PRG family is **secure** if for all adversaries, the PRG advantage is negligible.
(Definition 3.1 in Boneh-Shoup)
-/
def PRGFamily.Secure (G : PRGFamily) : Prop :=
  ∀ A : PRGAdversary G, Negligible (fun sp => PRGAdvantage G A sp)

section StreamCipher

/--
A **stream cipher** built from a PRG, where encryption XORs the PRG output with the message.
Given a PRG `G : BitVec s → BitVec n` (with `n > s`), the stream cipher encrypts as
`E(k, m) = G(k) ⊕ m` and decrypts as `D(k, c) = G(k) ⊕ c`.
(Section 3.2 in Boneh-Shoup)
-/
def streamCipher (seedLen msgLen : ℕ) (G : BitVec seedLen → BitVec msgLen) :
    ShannonCipher (BitVec seedLen) (BitVec msgLen) (BitVec msgLen) where
  encrypt k m := G k ^^^ m
  decrypt k c := G k ^^^ c
  correct k m := by rw [← BitVec.xor_assoc, BitVec.xor_self, BitVec.zero_xor]

end StreamCipher

end Cslib.Crypto

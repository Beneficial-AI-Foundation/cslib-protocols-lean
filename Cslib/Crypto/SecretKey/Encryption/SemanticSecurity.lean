/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.SecretKey.Encryption.ComputationalCipher
public import Mathlib.Data.Fintype.Card
public import Mathlib.Probability.ProbabilityMassFunction.Basic

@[expose] public section

/-!
# Semantic Security

This file formalizes semantic security via Attack Game 2.1 and the bit-guessing characterization
from Boneh-Shoup, Sections 2.2.2 and 2.2.5.

## Main definitions

- `SSAdversary`: An adversary for the semantic security attack game. The adversary chooses
  two messages of the same length, receives an encryption of one, and outputs a guess bit.

- `SSAdvantage`: The semantic security advantage `SSadv[A, E]` of an adversary `A` against
  a cipher family `E`, defined as `|Pr[W₀] - Pr[W₁]|`.

- `CipherFamily.SemanticallySecure`: A cipher family is semantically secure if `SSadv[A, E]`
  is negligible for all efficient adversaries.

## Main statements

- `SSAdvantage_eq_two_mul_bitGuessing`: `SSadv[A,E] = 2 · SSadv*[A,E]` (Theorem 2.10)

- `SemanticallySecure.secure_against_message_recovery`: Semantic security implies security
  against message recovery (Theorem 2.7)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Sections 2.2.2, 2.2.5, 2.3.4
-/

namespace Cslib.Crypto

/--
An **adversary** for the semantic security attack game (Attack Game 2.1).

For a cipher family `E`, at security parameter `λ`:
1. The adversary produces two messages `(m₀, m₁)` of the same length.
2. The challenger picks `k ←$ K`, computes `c ← E(k, mᵦ)`, and sends `c` to the adversary.
3. The adversary, given `c`, outputs a bit `b̂ ∈ {0, 1}`.

We model the adversary as two functions:
- `chooseMessages`: produces the pair `(m₀, m₁)`
- `distinguish`: given the ciphertext, outputs `true` (guess `b = 1`) or `false` (guess `b = 0`)
-/
structure SSAdversary (E : CipherFamily) where
  /-- The adversary's first phase: choose two challenge messages. -/
  chooseMessages : ∀ λ, E.Msg λ × E.Msg λ
  /-- The adversary's second phase: given a ciphertext, output a guess bit. -/
  distinguish : ∀ λ, E.Ctxt λ → Bool

/--
The probability that adversary `A` outputs `true` (i.e., guesses `b̂ = 1`) in Experiment `b`
of Attack Game 2.1, over the uniform choice of key `k`.

`Pr[Wᵦ] = |{k ∈ K : A.distinguish(E(k, mᵦ)) = true}| / |K|`
-/
noncomputable def SSExperimentProb [∀ λ, DecidableEq (E.Ctxt λ)]
    (E : CipherFamily) (A : SSAdversary E) (λ : ℕ) (b : Bool) : ℝ :=
  let msgs := A.chooseMessages λ
  let m := if b then msgs.2 else msgs.1
  (Finset.univ.filter fun (k : E.Key λ) =>
    A.distinguish λ (E.encrypt λ k m) = true).card / (Fintype.card (E.Key λ) : ℝ)

/--
The **semantic security advantage** of adversary `A` against cipher family `E` at security
parameter `λ`:

`SSadv[A, E](λ) := |Pr[W₀] - Pr[W₁]|`

where `Wᵦ` is the event that `A` outputs 1 in Experiment `b` of Attack Game 2.1.
(Section 2.2.2 / Attack Game 2.1)
-/
noncomputable def SSAdvantage [∀ λ, DecidableEq (E.Ctxt λ)]
    (E : CipherFamily) (A : SSAdversary E) (λ : ℕ) : ℝ :=
  Advantage (SSExperimentProb E A λ false) (SSExperimentProb E A λ true)

/--
A cipher family is **semantically secure** if for all adversaries, the function
`λ ↦ SSadv[A, E](λ)` is negligible.
(Definition 2.2 in Boneh-Shoup)
-/
def CipherFamily.SemanticallySecure [∀ λ, DecidableEq (E.Ctxt λ)] (E : CipherFamily) : Prop :=
  ∀ A : SSAdversary E, Negligible (fun λ => SSAdvantage E A λ)

/--
The **bit-guessing SS advantage** of adversary `A` against cipher `E` at security parameter `λ`:

`SSadv*[A, E](λ) := |Pr[b̂ = b] - 1/2|`

in the single-experiment version (Attack Game 2.4).
-/
noncomputable def SSBitGuessingAdvantage [∀ λ, DecidableEq (E.Ctxt λ)]
    (E : CipherFamily) (A : SSAdversary E) (λ : ℕ) : ℝ :=
  BitGuessingAdvantage
    ((1 - SSExperimentProb E A λ false + SSExperimentProb E A λ true) / 2)

/--
`SSadv[A, E] = 2 · SSadv*[A, E]` for every adversary `A` and cipher family `E`.
(Theorem 2.10 in Boneh-Shoup)
-/
theorem SSAdvantage_eq_two_mul_bitGuessing [∀ λ, DecidableEq (E.Ctxt λ)]
    (E : CipherFamily) (A : SSAdversary E) (λ : ℕ) :
    SSAdvantage E A λ = 2 * SSBitGuessingAdvantage E A λ := by
  unfold SSAdvantage SSBitGuessingAdvantage
  exact advantage_eq_two_mul_bitGuessing _ _

section MessageRecovery

/--
An adversary for the **message recovery** attack game (Attack Game 2.2).
The challenger picks `m ←$ M`, `k ←$ K`, computes `c ← E(k,m)`, sends `c` to the adversary,
and the adversary outputs a guess `m̂`.
-/
structure MRAdversary (E : CipherFamily) where
  /-- Given a ciphertext, output a guess for the underlying message. -/
  recover : ∀ λ, E.Ctxt λ → E.Msg λ

/--
The **message recovery advantage** of adversary `A` against cipher `E`:

`MRadv[A, E](λ) := |Pr[m̂ = m] - 1/|M||`

(Attack Game 2.2 in Boneh-Shoup)
-/
noncomputable def MRAdvantage [∀ λ, DecidableEq (E.Msg λ)] [∀ λ, DecidableEq (E.Ctxt λ)]
    (E : CipherFamily) (A : MRAdversary E) (λ : ℕ) : ℝ :=
  let numCorrect := (Finset.univ (α := E.Key λ ×ₗ E.Msg λ)).filter
    (fun ⟨k, m⟩ => A.recover λ (E.encrypt λ k m) = m) |>.card
  let total := Fintype.card (E.Key λ) * Fintype.card (E.Msg λ)
  |((numCorrect : ℝ) / total) - (1 / Fintype.card (E.Msg λ))|

/--
If a cipher is semantically secure, then it is secure against message recovery:
for every efficient MR adversary `A`, there exists an SS adversary `B` (an elementary wrapper
around `A`) such that `MRadv[A, E] ≤ SSadv[B, E]`.
(Theorem 2.7 in Boneh-Shoup)
-/
theorem SemanticallySecure.secure_against_message_recovery
    [∀ λ, DecidableEq (E.Msg λ)] [∀ λ, DecidableEq (E.Ctxt λ)]
    (E : CipherFamily) (hss : E.SemanticallySecure) :
    ∀ A : MRAdversary E, Negligible (fun λ => MRAdvantage E A λ) := by
  sorry

end MessageRecovery

end Cslib.Crypto

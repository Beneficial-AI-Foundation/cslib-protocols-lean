/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Init
public import Cslib.Crypto.Foundations.Negligible
public import Mathlib.Probability.ProbabilityMassFunction.Basic

@[expose] public section

/-!
# Advantage and Attack Games

This file formalizes the general framework of attack games, advantages, and the bit-guessing
characterization used throughout Boneh-Shoup (Sections 2.2.2, 2.2.5, 2.3.3).

## Main definitions

- `Advantage`: The advantage of an adversary in a two-experiment attack game, defined as
  `|Pr[W₀] - Pr[W₁]|` where `Wᵦ` is the event that the adversary outputs 1 in Experiment `b`.

- `BitGuessingAdvantage`: The bit-guessing advantage `|Pr[b̂ = b] - 1/2|` in the single-experiment
  version of an attack game.

## Main statements

- `advantage_eq_two_mul_bitGuessing`: `Xadv[A, S] = 2 · Xadv*[A, S]` (Theorem 2.10).

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Sections 2.2.2, 2.2.5
-/

namespace Cslib.Crypto

/--
The **advantage** of an adversary in a two-experiment attack game. Given probabilities `p₀` and `p₁`
that the adversary outputs 1 in Experiment 0 and Experiment 1 respectively, the advantage is
`|p₀ - p₁|`.

This captures the general pattern `Xadv[A, S] := |Pr[W₀] - Pr[W₁]|` from Section 2.2.5.1.
-/
noncomputable def Advantage (p₀ p₁ : ℝ) : ℝ := |p₀ - p₁|

/--
The **bit-guessing advantage** in the single-experiment version of an attack game.
Given `pWin`, the probability that the adversary correctly guesses the random bit `b`,
the bit-guessing advantage is `|pWin - 1/2|`.

This captures `Xadv*[A, S] := |Pr[W] - 1/2|` from Section 2.2.5.
-/
noncomputable def BitGuessingAdvantage (pWin : ℝ) : ℝ := |pWin - 1 / 2|

@[simp]
theorem Advantage.nonneg (p₀ p₁ : ℝ) : 0 ≤ Advantage p₀ p₁ := abs_nonneg _

@[simp]
theorem Advantage.le_one {p₀ p₁ : ℝ} (h₀ : 0 ≤ p₀) (h₀' : p₀ ≤ 1) (h₁ : 0 ≤ p₁)
    (h₁' : p₁ ≤ 1) : Advantage p₀ p₁ ≤ 1 := by
  unfold Advantage
  rw [abs_le]
  constructor <;> linarith

/--
The advantage equals twice the bit-guessing advantage.

For every cipher `E` and every adversary `A`, `Xadv[A, S] = 2 · Xadv*[A, S]`.
(Theorem 2.10 / equation (2.11) in Boneh-Shoup)

The proof follows the calculation in the book: if `p₀` and `p₁` are the probabilities the
adversary outputs 1 in Experiments 0 and 1 respectively, then in the bit-guessing game
`Pr[b̂ = b] = (1 - p₀ + p₁)/2`, so `SSadv* = |Pr[b̂ = b] - 1/2| = |p₁ - p₀|/2 = SSadv/2`.
-/
theorem advantage_eq_two_mul_bitGuessing (p₀ p₁ : ℝ) :
    Advantage p₀ p₁ = 2 * BitGuessingAdvantage ((1 - p₀ + p₁) / 2) := by
  unfold Advantage BitGuessingAdvantage
  rw [show (1 - p₀ + p₁) / 2 - 1 / 2 = (p₁ - p₀) / 2 by ring]
  rw [abs_div, show |(2 : ℝ)| = 2 from abs_of_pos two_pos]
  ring_nf
  rw [show p₀ - p₁ = -(p₁ - p₀) by ring, abs_neg]

end Cslib.Crypto

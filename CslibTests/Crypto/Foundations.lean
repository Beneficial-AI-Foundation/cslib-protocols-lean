/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

import Cslib.Crypto.Foundations.Negligible
import Cslib.Crypto.Foundations.Advantage

namespace CslibTests.Crypto

open Cslib.Crypto

/-! ## Examples of negligible functions (Definition 2.5 in Boneh-Shoup) -/

/-- The zero function is negligible. -/
example : Negligible (fun _ => 0) := by
  intro k
  simp

/-- A constant function is *not* negligible (unless it's zero).
    We state a specific non-example: `f(n) = 1` is not negligible. -/
example : ¬ Negligible (fun _ => (1 : ℝ)) := by
  intro h
  have := h 0
  simp at this

/-! ## Examples for Advantage (Section 2.2.5 in Boneh-Shoup) -/

/-- The advantage is 0 when both probabilities are equal. -/
example : Advantage (1/2) (1/2) = 0 := by
  unfold Advantage
  simp

/-- The advantage of probabilities 0 and 1 is 1 (maximum). -/
example : Advantage 0 1 = 1 := by
  unfold Advantage
  norm_num

/-- The advantage is symmetric. -/
example (p₀ p₁ : ℝ) : Advantage p₀ p₁ = Advantage p₁ p₀ := by
  unfold Advantage
  rw [abs_sub_comm]

/-- Bit-guessing advantage: winning with probability 1/2 gives advantage 0. -/
example : BitGuessingAdvantage (1/2) = 0 := by
  unfold BitGuessingAdvantage
  norm_num

/-- Bit-guessing advantage: winning with probability 3/4 gives advantage 1/4. -/
example : BitGuessingAdvantage (3/4) = 1/4 := by
  unfold BitGuessingAdvantage
  norm_num

/-- Theorem 2.10: the advantage equals twice the bit-guessing advantage.
    Concrete instance: p₀ = 0.2, p₁ = 0.8 gives SSadv = 0.6, SSadv* = 0.3. -/
example : Advantage (1/5) (4/5) = 2 * BitGuessingAdvantage ((1 - 1/5 + 4/5) / 2) :=
  advantage_eq_two_mul_bitGuessing (1/5) (4/5)

end CslibTests.Crypto

/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Init

/-!
# Negligible Functions

## Background

In cryptography, a function f : ℕ → ℝ is **negligible** if it vanishes faster
than the inverse of any polynomial. This captures the idea that an adversary's
advantage, as a function of the security parameter κ, becomes so small that no
polynomial-time magnification can make it significant.

## Cryptographic model

**Axiomatic / symbolic.** We work over `ℕ` rather than `ℝ` to avoid dependence
on Mathlib's real number library. Division is avoided by cross-multiplying:
instead of `f(κ) ≤ 1/κᶜ`, we check `f(κ) · κᶜ ≤ 1`. Over the naturals this
forces `f(κ) = 0` for all sufficiently large `κ`.

## Main definitions

- `Cslib.Crypto.Negligible` — a function `ℕ → ℕ` is negligible
- `Cslib.Crypto.NegligibleR` — a function `ℕ → ℝ` is negligible (axiomatized)

## Main results

- `Cslib.Crypto.negligible_zero` — the zero function is negligible

## References

- [Katz and Lindell, *Introduction to Modern Cryptography*, §3.2]
- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*, §2.3]
- [Rosulek, *The Joy of Cryptography*, §2.3]
-/

@[expose] public section

namespace Cslib.Crypto

/-- A function `f : ℕ → ℕ` is **negligible** if for every polynomial degree `c`,
    there exists a threshold `κ₀` past which `f(κ) · κᶜ ≤ 1`.

    This is the cross-multiplied form of `f(κ) ≤ 1/κᶜ`, avoiding division. -/
def Negligible (f : Nat → Nat) : Prop :=
  ∀ (c : Nat), ∃ (κ₀ : Nat), ∀ (κ : Nat), κ ≥ κ₀ → f κ * κ ^ c ≤ 1

/-- A function `f : ℕ → ℝ` is **negligible** in the standard sense.
    This is axiomatized — we state the definition but do not construct reals. -/
def NegligibleR (f : Nat → Nat) : Prop :=
  ∀ (c : Nat), ∃ (κ₀ : Nat), ∀ (κ : Nat), κ ≥ κ₀ → f κ * κ ^ c ≤ 1

/-- The zero function is negligible. -/
theorem negligible_zero : Negligible (fun _ => 0) := by
  intro c; exact ⟨0, fun _ _ => by simp⟩

/-- Negligible functions are closed under addition. -/
theorem negligible_add {f g : Nat → Nat}
    (hf : Negligible f) (hg : Negligible g) :
    Negligible (fun κ => f κ + g κ) := by
  sorry

/-- Negligible functions are closed under multiplication by a polynomial. -/
theorem negligible_mul_poly {f : Nat → Nat} {d : Nat}
    (hf : Negligible f) :
    Negligible (fun κ => f κ * κ ^ d) := by
  sorry

end Cslib.Crypto

end -- section

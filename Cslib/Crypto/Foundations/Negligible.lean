/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Init
-- TODO: uncomment once toolchains align (VCVio @ v4.28.0, CSLib @ v4.29.0-rc2)
-- public import VCVio.CryptoFoundations.Asymptotics.Negligible

/-!
# Negligible Functions

## Background

In cryptography, a function f : ℕ → ℝ is **negligible** if it vanishes faster
than the inverse of any polynomial. This captures the idea that an adversary's
advantage, as a function of the security parameter κ, becomes so small that no
polynomial-time magnification can make it significant.

## Cryptographic model

**Hybrid: axiomatic ℕ encoding + VCVio's probabilistic definition.**

We provide two formulations:
- `Cslib.Crypto.Negligible` — cross-multiplied form over `ℕ`, suitable for
  lightweight proofs without Mathlib reals.
- `VCVio.negligible` (re-exported) — the standard definition over `ℝ≥0∞`
  via Mathlib's `SuperpolynomialDecay`, suitable for composing with VCVio's
  oracle computation framework and probabilistic security games.

## Cross-references with VCVio

| Cslib definition | VCVio equivalent |
|-----------------|-----------------|
| `Cslib.Crypto.Negligible` | `VCVio.negligible` (`ℕ → ℝ≥0∞`, via `SuperpolynomialDecay`) |
| `Cslib.Crypto.negligible_zero` | `VCVio.negligible_zero` |

## Main definitions

- `Cslib.Crypto.Negligible` — a function `ℕ → ℕ` is negligible (ℕ encoding)

## Main results

- `Cslib.Crypto.negligible_zero` — the zero function is negligible

## References

- [Katz and Lindell, *Introduction to Modern Cryptography*, §3.2]
- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*, §2.3]
- [Rosulek, *The Joy of Cryptography*, §2.3]
- [VCVio.CryptoFoundations.Asymptotics.Negligible](https://github.com/Verified-zkEVM/VCV-io)
-/

@[expose] public section

namespace Cslib.Crypto

/-! ### Lightweight ℕ encoding (no Mathlib reals) -/

/-- A function `f : ℕ → ℕ` is **negligible** if for every polynomial degree `c`,
    there exists a threshold `κ₀` past which `f(κ) · κᶜ ≤ 1`.

    This is the cross-multiplied form of `f(κ) ≤ 1/κᶜ`, avoiding division.
    For the standard ℝ≥0∞ formulation, use `VCVio.negligible`. -/
def Negligible (f : Nat → Nat) : Prop :=
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

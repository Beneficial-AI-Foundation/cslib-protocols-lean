/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.Negligible

/-!
# Advantage Framework

## Background

The advantage of an adversary in a cryptographic security game measures how
much better than random guessing the adversary can distinguish or break a
scheme. The advantage is parameterized by the security parameter `κ`.

## Cryptographic model

**Axiomatic.** The advantage is an abstract function `Adversary → ℕ → ℕ`
mapping each adversary and security parameter to a natural number (numerator).
A separate denominator function normalizes the fraction. Security means the
advantage is negligible for all efficient adversaries.

This follows **approach #1** from the taxonomy of cryptographic formalization
strategies: hardness assumptions are axioms, and security reductions are
proved symbolically without computing concrete probabilities.

## Main definitions

- `Cslib.Crypto.Advantage` — bundles a numerator and denominator for advantage
- `Cslib.Crypto.Secure` — security as negligibility of advantage

## References

- [Katz and Lindell, *Introduction to Modern Cryptography*, §3.2]
- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*, §2.4]
-/

@[expose] public section

namespace Cslib.Crypto

/-- An advantage function bundles a numerator `adv` (mapping adversary and
    security parameter to a natural number) and a denominator `denom`. The
    actual advantage is `adv(A, κ) / denom(κ)`. -/
structure Advantage (Adversary : Type*) where
  /-- Advantage numerator: maps adversary and security parameter to ℕ. -/
  adv : Adversary → Nat → Nat
  /-- Denominator: normalizing factor at each security level. -/
  denom : Nat → Nat

/-- A scheme is **secure** with respect to an advantage function if for every
    adversary `A` and polynomial degree `c`, eventually:

      `adv(A, κ) · κᶜ ≤ denom(κ)`

    This encodes `adv(A, κ) / denom(κ) ≤ 1/κᶜ` by cross-multiplication. -/
def Secure {Adversary : Type*} (advantage : Advantage Adversary) : Prop :=
  ∀ (A : Adversary) (c : Nat),
    ∃ (κ₀ : Nat), ∀ (κ : Nat), κ ≥ κ₀ →
      advantage.adv A κ * κ ^ c ≤ advantage.denom κ

end Cslib.Crypto

end -- section

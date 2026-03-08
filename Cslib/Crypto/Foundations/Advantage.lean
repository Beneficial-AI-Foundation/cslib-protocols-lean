/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.Negligible
-- TODO: uncomment once toolchains align (VCVio @ v4.28.0, CSLib @ v4.29.0-rc2)
-- public import VCVio.CryptoFoundations.SecExp

/-!
# Advantage Framework

## Background

The advantage of an adversary in a cryptographic security game measures how
much better than random guessing the adversary can distinguish or break a
scheme. The advantage is parameterized by the security parameter `κ`.

## Cryptographic model

**Hybrid: axiomatic ℕ encoding + VCVio's probabilistic framework.**

We provide two formulations:
- `Cslib.Crypto.Advantage` / `Cslib.Crypto.Secure` — lightweight ℕ encoding
  with cross-multiplied negligibility, suitable for symbolic reductions.
- `VCVio.SecExp` / `VCVio.SecAdv` (re-exported) — probabilistic security
  experiments with `ProbComp`-based advantage computation over `ℝ≥0∞`.

## Cross-references with VCVio

| Cslib definition | VCVio equivalent |
|-----------------|-----------------|
| `Cslib.Crypto.Advantage` | `VCVio.SecExp` (security experiment) + `ProbComp.advantage` |
| `Cslib.Crypto.Secure` | `VCVio.SecExp.advantage` composed with `VCVio.negligible` |

The VCVio framework is strictly more expressive: it supports probabilistic
adversaries via `OracleComp`, oracle query tracking, and advantage computation
over real-valued distributions. Our `Advantage`/`Secure` is a lightweight
wrapper for symbolic proofs.

## Main definitions

- `Cslib.Crypto.Advantage` — bundles a numerator and denominator for advantage
- `Cslib.Crypto.Secure` — security as negligibility of advantage

## References

- [Katz and Lindell, *Introduction to Modern Cryptography*, §3.2]
- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*, §2.4]
- [VCVio.CryptoFoundations.SecExp](https://github.com/Verified-zkEVM/VCV-io)
-/

@[expose] public section

namespace Cslib.Crypto

/-- An advantage function bundles a numerator `adv` (mapping adversary and
    security parameter to a natural number) and a denominator `denom`. The
    actual advantage is `adv(A, κ) / denom(κ)`.

    For probabilistic advantage computation, use `VCVio.SecExp` with
    `ProbComp.advantage` instead. -/
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

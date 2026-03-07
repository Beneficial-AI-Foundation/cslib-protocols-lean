/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Init
public import Mathlib.Analysis.Asymptotics.SuperpolynomialDecay
public import Mathlib.Topology.Algebra.Order.LiminfLimsup

@[expose] public section

/-!
# Negligible, Super-Poly, and Poly-Bounded Functions

This file formalizes the asymptotic notions used throughout the Boneh-Shoup cryptography
framework (Section 2.3.1).

We build on Mathlib's `Asymptotics.SuperpolynomialDecay`, which captures the same notion as
Boneh-Shoup's "negligible": a function that decays faster than the inverse of any polynomial.

## Main definitions

- `Negligible`: A function `f : ℕ → ℝ` is negligible if for every `c > 0`, there exists `n₀`
  such that for all `n ≥ n₀`, `|f(n)| < 1/n^c`. (Definition 2.5)
  Equivalently, `Asymptotics.SuperpolynomialDecay Filter.atTop (↑· : ℕ → ℝ) f`.

- `SuperPoly`: A function `f : ℕ → ℝ` is super-poly if `1/f` is negligible. (Definition 2.6)

- `PolyBounded`: A function `f : ℕ → ℝ` is poly-bounded if there exist `c, d ∈ ℝ` such that
  for all `n ≥ 0`, `|f(n)| ≤ n^c + d`. (Definition 2.7)

## Main statements

- `Negligible.add'`: The sum of two negligible functions is negligible. (Fact 2.6(i))
- `PolyBounded.add`: The sum of two poly-bounded functions is poly-bounded. (Fact 2.6(ii))
- `PolyBounded.mul`: The product of two poly-bounded functions is poly-bounded. (Fact 2.6(ii))
- `PolyBounded.mul_negligible`: A poly-bounded function times a negligible function is
  negligible. (Fact 2.6(iii))

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Section 2.3.1
-/

namespace Cslib.Crypto

/--
A function `f : ℕ → ℝ` is **negligible** if for every positive real `c`, there exists a threshold
`n₀` such that for all `n ≥ n₀`, we have `|f(n)| < 1/n^c`.

This is equivalent to Mathlib's `Asymptotics.SuperpolynomialDecay` applied to the coercion
`(↑· : ℕ → ℝ)` and the filter `Filter.atTop`.

(Definition 2.5 in Boneh-Shoup)
-/
def Negligible (f : ℕ → ℝ) : Prop :=
  Asymptotics.SuperpolynomialDecay Filter.atTop (fun n : ℕ => (n : ℝ)) f

/--
A function `f : ℕ → ℝ` is **super-poly** if `1/f` is negligible.
(Definition 2.6 in Boneh-Shoup)
-/
def SuperPoly (f : ℕ → ℝ) : Prop :=
  Negligible (fun n => 1 / f n)

/--
A function `f : ℕ → ℝ` is **poly-bounded** if there exist constants `c` (a natural number) and
`d ≥ 0` (a real number) such that for all `n`, `|f(n)| ≤ n^c + d`.
(Definition 2.7 in Boneh-Shoup)
-/
def PolyBounded (f : ℕ → ℝ) : Prop :=
  ∃ (c : ℕ) (d : ℝ), d ≥ 0 ∧ ∀ n : ℕ, |f n| ≤ (n : ℝ) ^ c + d

/--
The sum of two negligible functions is negligible.
(Fact 2.6(i) in Boneh-Shoup)
-/
theorem Negligible.add' {f g : ℕ → ℝ} (hf : Negligible f) (hg : Negligible g) :
    Negligible (fun n => f n + g n) :=
  Asymptotics.SuperpolynomialDecay.add hf hg

/--
The sum of two poly-bounded functions is poly-bounded.
(Fact 2.6(ii) in Boneh-Shoup)
-/
theorem PolyBounded.add {f g : ℕ → ℝ} (_hf : PolyBounded f) (_hg : PolyBounded g) :
    PolyBounded (fun n => f n + g n) := by
  sorry

/--
The product of two poly-bounded functions is poly-bounded.
(Fact 2.6(ii) in Boneh-Shoup)
-/
theorem PolyBounded.mul {f g : ℕ → ℝ} (_hf : PolyBounded f) (_hg : PolyBounded g) :
    PolyBounded (fun n => f n * g n) := by
  sorry

/--
A poly-bounded function times a negligible function is negligible.
(Fact 2.6(iii) in Boneh-Shoup)
-/
theorem PolyBounded.mul_negligible {f g : ℕ → ℝ} (_hf : PolyBounded f) (_hg : Negligible g) :
    Negligible (fun n => f n * g n) := by
  sorry

/--
The equivalence between Boneh-Shoup's Definition 2.5 and the `Negligible` predicate
defined via `SuperpolynomialDecay`. This bridges the concrete ε-δ formulation with the
filter-based formulation.
(Theorem 2.11 in Boneh-Shoup)
-/
theorem negligible_iff_forall_pow_tendsto_zero (f : ℕ → ℝ) :
    Negligible f ↔
      ∀ k : ℕ, Filter.Tendsto (fun n : ℕ => (n : ℝ) ^ k * f n) Filter.atTop (nhds 0) :=
  Iff.rfl

end Cslib.Crypto

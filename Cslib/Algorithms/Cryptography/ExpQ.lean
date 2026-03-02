/-
Copyright (c) 2026 Christiano Braga. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Mathlib.Tactic

@[expose] public section

/-!
# Groups of Exponent q

These lemmas work over a commutative group $G$ whose every element has order dividing $q$,
where $q$ is prime. The key hypothesis throughout is:

  hG : ∀ x : G, x ^ q = 1

This is the defining property of a group of exponent $q$ — raising any element to the $q$-th
power gives the identity.
-/

namespace Cslib.Algorithms.Cryptography.ExpQ

variable {G : Type u} [CommGroup G] {q : ℕ} [Fact q.Prime]
variable (hG : ∀ x : G, x ^ q = 1)
include hG

/-
lemma pow_mod_eq — Exponents can be reduced mod $q$
  y ^ (n % q) = y ^ n

What it says: Exponentiating by $n$ is the same as exponentiating by $n \bmod q$.

Why it's true: By the division algorithm, $n = (n / q) \cdot q + (n \bmod q)$. So:
$$
  y^n = y^{(n/q) \cdot q + n \bmod q} =
      = y^{(n/q) \cdot q} \cdot y^{n \bmod q} =
      = (y^q)^{n/q} \cdot y^{n \bmod q}
      = 1^{n/q} \cdot y^{n \bmod q} = y^{n \bmod q}
$$

Why it matters: It lets you treat $\mathbb{N}$-valued exponents as living in ZMod q,
bridging Lean's natural number arithmetic with modular arithmetic.
-/
omit [Fact q.Prime] in
public lemma pow_mod_eq (y : G) (n : ℕ) : y ^ (n % q) = y ^ n := by
  conv_rhs => rw [(Nat.div_add_mod n q).symm]
  rw [pow_add, pow_mul, hG y, one_pow, one_mul]

/-
pow_val_mul — Multiplication in $\mathbb{Z}/q\mathbb{Z}$ corresponds to iterated exponentiation
  y ^ (a * b).val = (y ^ a.val) ^ b.val

What it says: If $a, b : \mathbb{Z}/q\mathbb{Z}$, then $y^{a \cdot b} = (y^a)^b$, where .val
extracts the natural number representative.

Why it's true: $(a \cdot b).\text{val}$ is $(a.\text{val} \cdot b.\text{val}) \bmod q$
(that's ZMod.val_mul). By pow_mod_eq, reducing mod $q$ doesn't change the power, so:
$$
  y^{(a.\text{val} \cdot b.\text{val}) \bmod q} =
  y^{a.\text{val} \cdot b.\text{val}} =
  (y^{a.\text{val}})^{b.\text{val}}
$$

Why it matters: This is essential where the response is computed as
$z = r + e \cdot w$ in $\mathbb{Z}/q\mathbb{Z}$, and verification checks that $g^z = a \cdot h^e$.
You need to move between modular multiplication and group exponentiation.
-/
omit [Fact q.Prime] in
public lemma pow_val_mul (y : G) (a b : ZMod q) :
    y ^ (a * b).val = (y ^ a.val) ^ b.val := by
  rw [ZMod.val_mul, pow_mod_eq hG, pow_mul]

/-
pow_val_sub — Subtraction in $\mathbb{Z}/q\mathbb{Z}$ corresponds to division in $G$
  y ^ (a - b).val = y ^ a.val * (y ^ b.val)⁻¹

What it says: $y^{a-b} = y^a / y^b$, where subtraction is in $\mathbb{Z}/q\mathbb{Z}$.

Why it's true: The proof shows $y^{a-b} \cdot y^b = y^a$ and then concludes by
"dividing both sides by $y^b$" (i.e., eq_mul_inv_of_mul_eq). The middle step uses:
  $y^{a-b} \cdot y^b = y^{(a-b)+b}$ (by pow_add)
  $y^{(a-b).\text{val} + b.\text{val}}$ is reduced mod $q$ via pow_mod_eq
  $(a - b) + b = a$ in $\mathbb{Z}/q\mathbb{Z}$ (by sub_add_cancel),
so the .vals match after reduction.

Why it matters: This is the key lemma for the special soundness (extraction) proof.
The extractor in Schnorr's protocol receives two accepting transcripts $(a, e, z)$ and $(a, e', z')$
and computes the witness as $w = (z - z') / (e - e')$. That division in the exponent is exactly what
this lemma justifies.
-/
public lemma pow_val_sub (y : G) (a b : ZMod q) :
    y ^ (a - b).val = y ^ a.val * (y ^ b.val)⁻¹ := by
  have h : y ^ (a - b).val * y ^ b.val = y ^ a.val := by
    rw [← pow_add, ← pow_mod_eq hG y ((a - b).val + b.val)]
    congr 1; rw [← ZMod.val_add, sub_add_cancel]
  exact eq_mul_inv_of_mul_eq h

end Cslib.Algorithms.Cryptography.ExpQ

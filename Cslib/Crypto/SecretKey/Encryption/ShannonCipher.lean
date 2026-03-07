/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Mathlib.Data.Fintype.Card
public import Mathlib.Probability.ProbabilityMassFunction.Basic
public import Mathlib.Data.BitVec.Lemmas

@[expose] public section

/-!
# Shannon Ciphers and Perfect Security

This file formalizes Shannon ciphers and perfect security from Chapter 2, Sections 2.1.1–2.1.3
of Boneh-Shoup.

## Main definitions

- `ShannonCipher`: A deterministic cipher `E = (E, D)` defined over `(K, M, C)` with
  encryption `E : K → M → C`, decryption `D : K → C → M`, and the correctness property
  `D(k, E(k, m)) = m`. (Section 2.1.1)

- `ShannonCipher.PerfectlySecure`: A Shannon cipher is perfectly secure if for all
  `m₀, m₁ ∈ M` and all `c ∈ C`, `Pr[E(k, m₀) = c] = Pr[E(k, m₁) = c]` where `k`
  is uniformly distributed over `K`. (Definition 2.1)

## Main statements

- `ShannonCipher.perfectlySecure_iff_uniform_preimage`: Equivalent characterization:
  for every `c`, the number of keys mapping any message to `c` is constant. (Theorem 2.1(ii))

- `ShannonCipher.perfectlySecure_card_key_ge_card_msg`: Shannon's theorem — if `E` is
  perfectly secure, then `|K| ≥ |M|`. (Theorem 2.5)

- `ShannonCipher.otp_perfectlySecure`: The one-time pad is perfectly secure. (Theorem 2.2)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Sections 2.1.1–2.1.3
-/

namespace Cslib.Crypto

/--
A **Shannon cipher** is a pair of functions `(encrypt, decrypt)` defined over finite types
`Key`, `Msg`, `Ctxt` (the key space, message space, and ciphertext space) satisfying the
**correctness property**: `decrypt k (encrypt k m) = m` for all keys `k` and messages `m`.

This corresponds to the definition in Section 2.1.1 of Boneh-Shoup.
-/
structure ShannonCipher (Key Msg Ctxt : Type*) where
  /-- The encryption function `E : K × M → C`. -/
  encrypt : Key → Msg → Ctxt
  /-- The decryption function `D : K × C → M`. -/
  decrypt : Key → Ctxt → Msg
  /-- The correctness property: decryption undoes encryption. -/
  correct : ∀ k m, decrypt k (encrypt k m) = m

variable {Key Msg Ctxt : Type*}

/--
A Shannon cipher is **perfectly secure** if for all messages `m₀, m₁` and all ciphertexts `c`,
the number of keys that encrypt `m₀` to `c` equals the number of keys that encrypt `m₁` to `c`.

This is equivalent to Definition 2.1 in Boneh-Shoup: when `k` is uniformly distributed over `K`,
`Pr[E(k, m₀) = c] = Pr[E(k, m₁) = c]` for all `m₀, m₁, c`.

We use the counting formulation (Theorem 2.1(ii)) as it avoids the need for measure theory
and is equivalent over finite types.
-/
def ShannonCipher.PerfectlySecure [DecidableEq Ctxt] [Fintype Key] (E : ShannonCipher Key Msg Ctxt) : Prop :=
  ∀ (m₀ m₁ : Msg) (c : Ctxt),
    (Finset.univ.filter fun k => E.encrypt k m₀ = c).card =
    (Finset.univ.filter fun k => E.encrypt k m₁ = c).card

/--
**Shannon's theorem** (Theorem 2.5): If a Shannon cipher is perfectly secure,
then the key space is at least as large as the message space: `|K| ≥ |M|`.
-/
theorem ShannonCipher.perfectlySecure_card_key_ge_card_msg
    [DecidableEq Ctxt] [DecidableEq Msg] [Fintype Key] [Fintype Msg]
    (E : ShannonCipher Key Msg Ctxt) (hps : E.PerfectlySecure) :
    Fintype.card Key ≥ Fintype.card Msg := by
  sorry

section OneTimePad

/--
The **one-time pad** is a Shannon cipher where the key space, message space, and ciphertext space
are all `BitVec n`, encryption is XOR, and decryption is also XOR.
(Example 2.1 in Boneh-Shoup)
-/
def otp (n : ℕ) : ShannonCipher (BitVec n) (BitVec n) (BitVec n) where
  encrypt k m := k ^^^ m
  decrypt k c := k ^^^ c
  correct k m := by simp [BitVec.xor_assoc, BitVec.xor_self, BitVec.zero_xor]

/--
The one-time pad is perfectly secure.
(Theorem 2.2 in Boneh-Shoup)

The proof follows the book: for any fixed message `m` and ciphertext `c`, there is exactly
one key `k = m ⊕ c` such that `k ⊕ m = c`.
-/
theorem otp_perfectlySecure (n : ℕ) : (otp n).PerfectlySecure := by
  sorry

end OneTimePad

section AdditiveOTP

/--
The **additive one-time pad** modulo `n`: encryption is addition mod `n`, decryption is
subtraction mod `n`. (Example 2.4 in Boneh-Shoup)
-/
def additiveOtp (n : ℕ) [NeZero n] : ShannonCipher (ZMod n) (ZMod n) (ZMod n) where
  encrypt k m := m + k
  decrypt k c := c - k
  correct k m := by simp [add_sub_cancel_right]

/--
The additive one-time pad is perfectly secure. (Example 2.7 in Boneh-Shoup)
-/
theorem additiveOtp_perfectlySecure (n : ℕ) [NeZero n] :
    (additiveOtp n).PerfectlySecure := by
  sorry

end AdditiveOTP

end Cslib.Crypto

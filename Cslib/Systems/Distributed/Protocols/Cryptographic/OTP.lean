/-
Copyright (c) 2026 Christiano Braga. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Algorithms.Cryptography.Cyphertext

@[expose] public section

/-!
# One-Time Pad protocol

A *one-time pad* is a cipher where the key space, message space, and ciphertext space
are all equal to `{0,1}ⁿ` for some `n`. Given a key `k` chosen uniformly at random from `{0,1}ⁿ`:

- **Encryption:** `E(k, m) = k ⊕ m`
- **Decryption:** `D(k, c) = k ⊕ c`

where `⊕` denotes bitwise XOR.

The one-time pad achieves **perfect secrecy** (Shannon secrecy): for every pair of messages `m₀, m₁`
and every ciphertext `c`, the probability that `c` was produced from `m₀` equals the probability it
was produced from `m₁`, when the key is uniformly random. Formally:

> `Pr[E(k, m₀) = c] = Pr[E(k, m₁) = c]`

**Key constraint:** The key must be at least as long as the message and must **never be reused** —
hence the name "one-time" pad. Reusing a key `k` for two messages `m₁` and `m₂` leaks `m₁ ⊕ m₂`,
destroying security.

Reference:

* [D. Boneh and V. Shoup,V., *A Graduate Course in Applied Cryptography*, One-time pad][BonehShoup], Section 2.1.
-/

namespace Cslib.Systems.Distributed.Protocols.Cryptographic.OTP

open Cslib.Algorithms.Cryptography.Shannon.Cyphertext

variable {n : Nat}

namespace OTP

-- Encryption: c = m XOR k
def encrypt (m k : Bits n) : Bits n := xorBits m k

-- Decryption: m = c XOR k (same operation)
def decrypt (c k : Bits n) : Bits n := xorBits c k

theorem correctness (m k : Bits n) :
    decrypt (encrypt m k) k = m :=
  xorBits_cancel m k

/-
Perfect Secrecy (Shannon)
For any message m and ciphertext c, there exists a unique
key k such that encrypt(m, k) = c
-/
theorem unique_key (m c : Bits n) :
    ∃ k : Bits n, encrypt m k = c ∧ ∀ k' : Bits n,
      encrypt m k' = c → k' = k := by
  refine ⟨xorBits m c, xorBits_left_cancel m c, ?_⟩
  intro k' hk'
  unfold encrypt at hk'
  have h := (xorBits_left_cancel m k').symm
  rwa [hk'] at h

/-
Perfect secrecy (Shannon): every ciphertext is consistent with every message
(for an appropriate key) — this is perfect secrecy. Shannon's perfect secrecy
is not expressed in terms of probability but as a weaker proposition as an
existential quantification of a key that relates a message to a cyphertext.
The uniqueness theorem is actually a stronger proposition that constraint a key
k to be unique.
-/
theorem perfect_secrecy (m₁ c : Bits n) :
    ∃ k : Bits n, encrypt m₁ k = c :=
  ⟨xorBits m₁ c, xorBits_left_cancel m₁ c⟩

end OTP

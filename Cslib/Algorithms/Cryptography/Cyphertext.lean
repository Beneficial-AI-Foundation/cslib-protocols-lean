/-
Copyright (c) 2026 Christiano Braga. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

@[expose] public section

/-!
# (Shannon) Cyphertext formalization

A message, key, or ciphertext is a vector of bits of length n.
-/

namespace Cslib.Algorithms.Cryptography.Shannon.Cyphertext

variable {n : Nat}

-- A message/key/ciphertext is a vector of bits of length n
public def Bits (n) := Fin n → Bool

-- XOR on bits
public def xorBits {n} (a b : Bits n) : Bits n :=
  fun i => xor (a i) (b i)

-- XOR is its own inverse
public theorem xorBits_cancel (a b : Bits n) : xorBits (xorBits a b) b = a := by
  funext i; simp [xorBits]

public theorem xorBits_left_cancel (a b : Bits n) : xorBits a (xorBits a b) = b := by
  funext i; simp [xorBits]

end Cslib.Algorithms.Cryptography.Shannon.Cyphertext

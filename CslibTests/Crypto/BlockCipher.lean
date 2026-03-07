/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

import Cslib.Crypto.SecretKey.BlockCipher.PRF

namespace CslibTests.Crypto

open Cslib.Crypto

/-! ## Block cipher example (Section 4.1 in Boneh-Shoup)

We construct a tiny block cipher over `Fin 4` with `Fin 2` keys,
where key 0 maps to the identity permutation and key 1 maps to
the swap of 0↔1 and 2↔3.
-/

/-- A tiny block cipher family: constant across security parameters,
    operating on `Fin 4` blocks with `Fin 2` keys. -/
def tinyBlockCipher : BlockCipherFamily where
  Key _ := Fin 2
  Block _ := Fin 4
  key_fintype _ := inferInstance
  block_fintype _ := inferInstance
  key_nonempty _ := inferInstance
  block_nonempty _ := inferInstance
  block_deceq _ := inferInstance
  perm _ k :=
    if k = 0 then Equiv.refl _
    else Equiv.swap (0 : Fin 4) (1 : Fin 4) * Equiv.swap (2 : Fin 4) (3 : Fin 4)

/-- Correctness: decryption inverts encryption. -/
example (sp : ℕ) (k : Fin 2) (x : Fin 4) :
    tinyBlockCipher.decrypt sp k (tinyBlockCipher.encrypt sp k x) = x :=
  tinyBlockCipher.correct sp k x

/-- Conversion to CipherFamily preserves correctness. -/
example (sp : ℕ) (k : Fin 2) (m : Fin 4) :
    tinyBlockCipher.toCipherFamily.decrypt sp k (tinyBlockCipher.toCipherFamily.encrypt sp k m) = m :=
  tinyBlockCipher.toCipherFamily.correct sp k m

/-! ## PRF from block cipher (Section 4.4 in Boneh-Shoup) -/

/-- Convert our tiny block cipher to a PRF family. -/
def tinyPRF : PRFFamily := tinyBlockCipher.toPRFFamily

/-- The PRF evaluates the same as the block cipher encryption. -/
example (sp : ℕ) (k : Fin 2) (x : Fin 4) :
    tinyPRF.eval sp k x = tinyBlockCipher.encrypt sp k x := rfl

end CslibTests.Crypto

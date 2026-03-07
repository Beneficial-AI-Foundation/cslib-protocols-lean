/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

import Cslib.Crypto.SecretKey.Encryption.ShannonCipher

namespace CslibTests.Crypto

open Cslib.Crypto

/-! ## One-Time Pad examples (Example 2.1 in Boneh-Shoup) -/

/-- OTP correctness: encrypting then decrypting with the same key returns the original. -/
example (k m : BitVec 8) : (otp 8).decrypt k ((otp 8).encrypt k m) = m :=
  (otp 8).correct k m

/-- Specific OTP example: key = 0xAB, message = 0x42. -/
example : (otp 8).encrypt 0xAB#8 0x42#8 = 0xE9#8 := by native_decide

/-- OTP encryption is an involution: encrypting twice gives back the original. -/
example (k m : BitVec 8) : (otp 8).encrypt k ((otp 8).encrypt k m) = m :=
  (otp 8).correct k m

/-! ## Additive OTP over Z/nZ (Example 2.4 in Boneh-Shoup) -/

/-- Additive OTP correctness over Z/26Z (the alphabet). -/
example (k m : ZMod 26) : (additiveOtp 26).decrypt k ((additiveOtp 26).encrypt k m) = m :=
  (additiveOtp 26).correct k m

/-- Concrete example: key = 3, message = 7 in Z/26Z gives ciphertext 10. -/
example : (additiveOtp 26).encrypt (3 : ZMod 26) (7 : ZMod 26) = (10 : ZMod 26) := by
  native_decide

/-! ## Substitution cipher as a Shannon cipher (Example 2.2 in Boneh-Shoup) -/

/-- A tiny substitution cipher over `Fin 3` (alphabet {0,1,2}).
    The key is a permutation of the alphabet. -/
def tinySubstitution : ShannonCipher (Equiv.Perm (Fin 3)) (Fin 3) (Fin 3) where
  encrypt π m := π m
  decrypt π c := π.symm c
  correct π m := π.symm_apply_apply m

/-- Correctness of the tiny substitution cipher. -/
example (π : Equiv.Perm (Fin 3)) (m : Fin 3) :
    tinySubstitution.decrypt π (tinySubstitution.encrypt π m) = m :=
  tinySubstitution.correct π m

/-! ## Cipher over a binary field (Fin 2) -/

/-- The XOR cipher over `Fin 2` is a valid Shannon cipher. -/
def fin2Cipher : ShannonCipher (Fin 2) (Fin 2) (Fin 2) where
  encrypt k m := k + m
  decrypt k c := c - k
  correct k m := by simp [add_sub_cancel_right]

example : fin2Cipher.encrypt 1 0 = 1 := by native_decide
example : fin2Cipher.encrypt 1 1 = 0 := by native_decide

end CslibTests.Crypto

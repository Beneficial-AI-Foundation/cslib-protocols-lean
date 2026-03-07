/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

import Cslib.Crypto.SecretKey.StreamCipher.PRG

namespace CslibTests.Crypto

open Cslib.Crypto

/-! ## Stream cipher example (Section 3.2 in Boneh-Shoup)

A stream cipher built from a simple (insecure) "PRG" that doubles a 4-bit seed
to an 8-bit output by concatenation. This is for demonstration only.
-/

/-- A toy "PRG": double a 4-bit value to 8 bits by concatenation.
    This is NOT a secure PRG, just a structural example. -/
def toyPRG : BitVec 4 → BitVec 8 := fun s =>
  s ++ s

/-- Build a stream cipher from our toy PRG. -/
def toyStreamCipher := streamCipher 4 8 toyPRG

/-- Stream cipher correctness: decryption undoes encryption. -/
example (k : BitVec 4) (m : BitVec 8) :
    toyStreamCipher.decrypt k (toyStreamCipher.encrypt k m) = m :=
  toyStreamCipher.correct k m

/-- Concrete stream cipher example. -/
example : toyStreamCipher.encrypt 0xA#4 0x42#8 = (toyPRG 0xA#4 ^^^ 0x42#8) := rfl

end CslibTests.Crypto

/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

import Cslib.Crypto.SecretKey.Encryption.SemanticSecurity

namespace CslibTests.Crypto

open Cslib.Crypto

/-! ## Cipher family examples (Definition 2.10 in Boneh-Shoup)

We construct a family of XOR ciphers indexed by security parameter,
where at security parameter `sp` the key, message, and ciphertext spaces
are all `Fin (2^sp)`.
-/

/-- A family of additive ciphers over `ZMod (sp + 1)`.
    At security parameter `sp`, the cipher operates over `ZMod (sp + 1)`. -/
def additiveCipherFamily : CipherFamily where
  Key sp := ZMod (sp + 1)
  Msg sp := ZMod (sp + 1)
  Ctxt sp := ZMod (sp + 1)
  key_fintype sp := inferInstance
  msg_fintype sp := inferInstance
  ctxt_fintype sp := inferInstance
  key_nonempty sp := inferInstance
  encrypt sp k m := m + k
  decrypt sp k c := c - k
  correct sp k m := by simp [add_sub_cancel_right]

/-- Correctness holds at every security parameter. -/
example (sp : ℕ) (k m : ZMod (sp + 1)) :
    additiveCipherFamily.decrypt sp k (additiveCipherFamily.encrypt sp k m) = m :=
  additiveCipherFamily.correct sp k m

/-! ## Semantic security adversary example (Attack Game 2.1)

A trivial adversary that always outputs `false` has zero advantage.
-/

/-- The trivial adversary that always guesses 0 (outputs `false`). -/
def trivialAdversary : SSAdversary additiveCipherFamily where
  chooseMessages sp :=
    let z : ZMod (sp + 1) := 0
    (z, z)
  distinguish _ _ := false

/-- The trivial adversary has zero SS advantage at any security parameter,
    since it always outputs `false` in both experiments. -/
example (sp : ℕ) : SSAdvantage additiveCipherFamily trivialAdversary sp = 0 := by
  unfold SSAdvantage Advantage SSExperimentProb
  simp [trivialAdversary]

end CslibTests.Crypto

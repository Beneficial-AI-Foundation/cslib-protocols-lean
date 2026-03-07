/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.Advantage

/-!
# Key Derivation Functions (KDF) and PRF Security

## Background

A Key Derivation Function (KDF) derives one or more cryptographic keys from
a source of keying material (e.g., a shared secret). The standard security
model for KDFs is **PRF security**: the output of the KDF is indistinguishable
from a truly random function.

Signal uses HKDF (HMAC-based Key Derivation Function) throughout its
protocol stack:
- In PQXDH, to derive the session key from multiple DH and KEM shared secrets.
- In the Double Ratchet, to advance the symmetric ratchet chain.
- In SPQR, to derive keys from the triple ratchet state.

## Cryptographic model

**Axiomatic.** We define the KDF and PRF interfaces and state PRF security
as negligibility of an axiomatized advantage function.

## Main definitions

- `Cslib.Crypto.KDF` — type class for key derivation functions
- `Cslib.Crypto.PRFAdversary` — adversary for the PRF distinguishing game
- `Cslib.Crypto.PRFSecure` — PRF security as negligibility of advantage

## References

- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*, Ch. 4]
- [Rosulek, *The Joy of Cryptography*, Ch. 6]
- [Krawczyk, *Cryptographic Extraction and Key Derivation: The HKDF Scheme*]
-/

@[expose] public section

namespace Cslib.Crypto

/-- A Key Derivation Function.

    `K` = input key material, `Salt` = optional salt, `Info` = context info,
    `OKM` = output keying material. -/
class KDF (K Salt Info OKM : Type*) where
  /-- Derive output keying material from input key material. -/
  derive : K → Salt → Info → OKM

/-- A Pseudorandom Function (PRF).

    `K` = key, `X` = input domain, `Y` = output range. -/
class PRF (K X Y : Type*) where
  /-- Evaluate the PRF: key → input → output. -/
  eval : K → X → Y

/-! ### PRF security game -/

/-- A PRF adversary: given oracle access to either a keyed PRF or a truly
    random function, must distinguish the two cases. -/
structure PRFAdversary (X Y : Type*) (State : Type*) where
  /-- Given oracle access to a function `X → Y`, produce a state. -/
  query : (X → Y) → State
  /-- Given the state, output a bit: `true` = PRF, `false` = random. -/
  decide : State → Bool

/-- PRF security: no efficient adversary can distinguish the PRF from a
    random function with non-negligible advantage. -/
def PRFSecure (X Y : Type*) (State : Type*)
    (advantage : Advantage (PRFAdversary X Y State)) : Prop :=
  Secure advantage

/-! ### Dual-PRF security -/

/-- Dual-PRF security: the function is a secure PRF when keyed on *either*
    input. This property is used in Signal's HKDF constructions where the
    salt and key roles can be swapped. -/
def DualPRFSecure (X Y : Type*) (State : Type*)
    (advantage_keyed : Advantage (PRFAdversary X Y State))
    (advantage_salted : Advantage (PRFAdversary X Y State)) : Prop :=
  PRFSecure X Y State advantage_keyed ∧ PRFSecure X Y State advantage_salted

end Cslib.Crypto

end -- section

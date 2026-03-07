/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.Advantage

/-!
# Authenticated Encryption with Associated Data (AEAD)

## Background

AEAD is the standard symmetric-key encryption primitive used in modern
protocols. It provides both **confidentiality** (IND-CPA) and **integrity**
(INT-CTXT) in a single interface. An AEAD scheme takes a key, a nonce,
plaintext, and associated data (authenticated but not encrypted), and
produces a ciphertext with an authentication tag.

Signal's Double Ratchet and SPQR protocols use AEAD for encrypting
individual messages after the shared secret has been established.

## Cryptographic model

**Axiomatic.** We define the AEAD interface and state the security
properties (IND-CPA and INT-CTXT) as negligibility of axiomatized
advantage functions.

## Main definitions

- `Cslib.Crypto.AEADScheme` — type class for AEAD (Encrypt, Decrypt)
- `Cslib.Crypto.AEADCorrect` — correctness: decrypt recovers plaintext
- `Cslib.Crypto.AEADINDCPASecure` — IND-CPA security for AEAD
- `Cslib.Crypto.AEADINTCTXTSecure` — INT-CTXT security for AEAD

## References

- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*, Ch. 9]
- [Rosulek, *The Joy of Cryptography*, Ch. 10]
- [Rogaway, *Authenticated-Encryption with Associated-Data*]
-/

@[expose] public section

namespace Cslib.Crypto

/-- An Authenticated Encryption with Associated Data (AEAD) scheme.

    `K` = key, `N` = nonce, `M` = plaintext, `C` = ciphertext,
    `AD` = associated data. -/
class AEADScheme (K N M C AD : Type*) where
  /-- Encryption: key → nonce → associated data → plaintext → ciphertext. -/
  encrypt : K → N → AD → M → C
  /-- Decryption: key → nonce → associated data → ciphertext → plaintext or ⊥.
      Returns `none` if authentication fails. -/
  decrypt : K → N → AD → C → Option M

/-- Correctness of AEAD: decryption recovers the plaintext for honest ciphertexts. -/
def AEADCorrect [AEADScheme K N M C AD] : Prop :=
  ∀ (k : K) (n : N) (ad : AD) (m : M),
    AEADScheme.decrypt k n ad (AEADScheme.encrypt (C := C) k n ad m) = some m

/-! ### IND-CPA security for AEAD -/

/-- An IND-CPA adversary for AEAD: given an encryption oracle (that
    encrypts one of two chosen messages), must distinguish which was encrypted. -/
structure AEADCPAAdversary (K N M C AD : Type*) (State : Type*) where
  /-- Phase 1: produce two messages, a nonce, associated data, and state. -/
  choose : N × AD × M × M × State
  /-- Phase 2: given the challenge ciphertext and state, output a bit. -/
  guess  : C → State → Bool

/-- IND-CPA security for AEAD. -/
def AEADINDCPASecure (K N M C AD : Type*) (State : Type*)
    (advantage : Advantage (AEADCPAAdversary K N M C AD State)) : Prop :=
  Secure advantage

/-! ### INT-CTXT (ciphertext integrity) security for AEAD -/

/-- An INT-CTXT adversary: given an encryption oracle, must forge a
    ciphertext that decrypts successfully but was never produced by
    the oracle. -/
structure AEADINTCTXTAdversary (K N M C AD : Type*) where
  /-- Given access to an encryption oracle, produce a forgery
      (nonce, associated data, ciphertext) that was never encrypted. -/
  forge : (N → AD → M → C) → N × AD × C

/-- INT-CTXT security for AEAD: no efficient adversary can forge a
    valid ciphertext. -/
def AEADINTCTXTSecure (K N M C AD : Type*)
    (advantage : Advantage (AEADINTCTXTAdversary K N M C AD)) : Prop :=
  Secure advantage

end Cslib.Crypto

end -- section

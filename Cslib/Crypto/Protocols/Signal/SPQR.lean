/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Protocols.Signal.TripleRatchet

/-!
# SPQR: Signal's Post-Quantum Ratchet

## Background

SPQR (Signal Post-Quantum Ratchet) is Signal's production post-quantum
messaging protocol. It builds on the Triple Ratchet architecture, using
the ML-KEM Braid construction for the post-quantum ratchet layer.

SPQR is designed as a drop-in upgrade to the Double Ratchet: it is
backwards-compatible with existing Double Ratchet sessions and can
be incrementally adopted.

The key innovation is the interleaving of KEM operations with the existing
DH ratchet, achieving post-quantum security without a separate ratchet
round-trip, by amortizing KEM operations across multiple messages.

## Cryptographic model

**Axiomatic / stub.** The SPQR protocol is specified as an extension of
the Triple Ratchet. Security reduces to the Triple Ratchet security
theorem plus additional properties of the braid integration.

## Main definitions

- `Cslib.Crypto.Signal.SPQRState` — the SPQR protocol state
- `Cslib.Crypto.Signal.spqrEncrypt` — encrypt a message via SPQR
- `Cslib.Crypto.Signal.spqrDecrypt` — decrypt a message via SPQR
- `Cslib.Crypto.Signal.SPQRSecure` — full SPQR security

## References

- [Signal, *SPQR*](https://signal.org/docs/specifications/doubleratchet)
- [Signal blog, *SPQR*](https://signal.org/blog/spqr/)
- [Balli et al., *SPQR: Signal's Post-Quantum Ratchet*](https://eprint.iacr.org/2025/2267.pdf)
- [PQShield analysis](https://pqshield.com/diving-into-signals-new-pq-protocol/)
-/

@[expose] public section

namespace Cslib.Crypto.Signal

/-- The SPQR protocol state.
    Wraps a Triple Ratchet state with additional metadata for backwards
    compatibility and braid scheduling. -/
structure SPQRState (G Scalar RootKey CK MK PK_KEM SK_KEM SS : Type*) where
  /-- The underlying Triple Ratchet state. -/
  tripleRatchet : TripleRatchetState G Scalar RootKey CK MK PK_KEM SK_KEM SS
  /-- Whether the remote peer supports SPQR (for backwards compatibility). -/
  peerSupportsKEM : Bool
  /-- Braid scheduling: number of messages until next KEM ratchet. -/
  kemScheduleCounter : Nat

/-- Encrypt a message via SPQR.
    If the peer supports KEM, uses the Triple Ratchet with braid.
    Otherwise, falls back to the Double Ratchet. -/
def spqrEncrypt
    {G Scalar RootKey CK MK PK_KEM SK_KEM SS CT R M C AD : Type*}
    [KEMScheme PK_KEM SK_KEM CT SS R]
    [AEADScheme MK (MessageHeader G) M C AD]
    (_state : SPQRState G Scalar RootKey CK MK PK_KEM SK_KEM SS)
    (_plaintext : M)
    (_ad : AD) :
    SPQRState G Scalar RootKey CK MK PK_KEM SK_KEM SS × MessageHeader G × C :=
  sorry

/-- Decrypt a message via SPQR. -/
def spqrDecrypt
    {G Scalar RootKey CK MK PK_KEM SK_KEM SS CT R M C AD : Type*}
    [KEMScheme PK_KEM SK_KEM CT SS R]
    [AEADScheme MK (MessageHeader G) M C AD]
    (_state : SPQRState G Scalar RootKey CK MK PK_KEM SK_KEM SS)
    (_header : MessageHeader G)
    (_ciphertext : C)
    (_ad : AD) :
    Option (SPQRState G Scalar RootKey CK MK PK_KEM SK_KEM SS × M) :=
  sorry

/-- Full SPQR security: forward secrecy, classical PCS, and PQ-PCS. -/
def SPQRSecure
    (Adversary : Type*) (advantage : Advantage Adversary) : Prop :=
  Secure advantage

/-- SPQR security reduces to Triple Ratchet security (statement only). -/
theorem spqr_security
    {G Scalar RootKey CK MK PK_KEM SK_KEM SS : Type*}
    {Adv : Type*}
    (_h_cdh : CDHSecure G sorry)
    (_h_kem : KEMINDCCA2Secure PK_KEM Unit SS Unit sorry)
    (_h_prf : PRFSecure CK MK Unit sorry) :
    SPQRSecure Adv sorry := by
  sorry

end Cslib.Crypto.Signal

end -- section

/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Protocols.Signal.DoubleRatchet
public import Cslib.Crypto.Protocols.Signal.MLKEMBraid

/-!
# Triple Ratchet Protocol

## Background

The Triple Ratchet extends the Double Ratchet with a third ratcheting
mechanism based on a post-quantum KEM (via the ML-KEM Braid construction).
This provides **post-quantum post-compromise security**: even after a state
compromise, security is restored with post-quantum guarantees once a new
KEM exchange completes.

The three ratchets are:
1. **Symmetric ratchet** — per-message forward secrecy (same as Double Ratchet)
2. **DH ratchet** — classical post-compromise security (same as Double Ratchet)
3. **KEM ratchet** — post-quantum post-compromise security (new in Triple Ratchet)

## Cryptographic model

**Axiomatic / stub.** The state and transitions are specified. The security
theorem reduces to CDH, KEM IND-CCA2, KDF PRF security, and AEAD security.

## Main definitions

- `Cslib.Crypto.Signal.TripleRatchetState` — the full triple ratchet state
- `Cslib.Crypto.Signal.tripleRatchetEncrypt` — encrypt a message
- `Cslib.Crypto.Signal.tripleRatchetDecrypt` — decrypt a message
- `Cslib.Crypto.Signal.PQPostCompromiseSecure` — PQ-PCS property

## References

- [Bienstock et al., *Triple Ratchet*](https://eprint.iacr.org/2025/078.pdf)
- [Signal, *The Double Ratchet Algorithm*](https://signal.org/docs/specifications/doubleratchet)
-/

@[expose] public section

namespace Cslib.Crypto.Signal

/-- The full Triple Ratchet state.
    Extends the Double Ratchet state with a KEM ratchet (braid). -/
structure TripleRatchetState (G Scalar RootKey CK MK PK_KEM SK_KEM SS : Type*) where
  /-- The Double Ratchet component (DH + symmetric ratchets). -/
  doubleRatchet : RatchetState G Scalar RootKey CK MK
  /-- The KEM ratchet component (ML-KEM Braid). -/
  kemBraid : BraidState PK_KEM SK_KEM SS

/-- Encrypt a message using the Triple Ratchet. -/
def tripleRatchetEncrypt
    {G Scalar RootKey CK MK PK_KEM SK_KEM SS CT R M C AD : Type*}
    [KEMScheme PK_KEM SK_KEM CT SS R]
    [AEADScheme MK (MessageHeader G) M C AD]
    (_state : TripleRatchetState G Scalar RootKey CK MK PK_KEM SK_KEM SS)
    (_plaintext : M)
    (_ad : AD) :
    TripleRatchetState G Scalar RootKey CK MK PK_KEM SK_KEM SS × MessageHeader G × C :=
  sorry

/-- Decrypt a message using the Triple Ratchet. -/
def tripleRatchetDecrypt
    {G Scalar RootKey CK MK PK_KEM SK_KEM SS CT R M C AD : Type*}
    [KEMScheme PK_KEM SK_KEM CT SS R]
    [AEADScheme MK (MessageHeader G) M C AD]
    (_state : TripleRatchetState G Scalar RootKey CK MK PK_KEM SK_KEM SS)
    (_header : MessageHeader G)
    (_ciphertext : C)
    (_ad : AD) :
    Option (TripleRatchetState G Scalar RootKey CK MK PK_KEM SK_KEM SS × M) :=
  sorry

/-! ### Security properties -/

/-- Post-quantum post-compromise security (PQ-PCS): after a state compromise,
    security is restored with post-quantum guarantees once a new KEM ratchet
    step completes.

    This is the key property that the Triple Ratchet adds over the Double
    Ratchet — the DH ratchet's PCS is only classical. -/
def PQPostCompromiseSecure
    (Adversary : Type*) (advantage : Advantage Adversary) : Prop :=
  Secure advantage

/-- The Triple Ratchet provides forward secrecy, classical PCS, and PQ-PCS
    (statement only). -/
theorem triple_ratchet_security
    {G Scalar RootKey CK MK PK_KEM SK_KEM SS : Type*}
    {Adv_FS Adv_PCS Adv_PQPCS : Type*}
    (_h_cdh : CDHSecure G sorry)
    (_h_kem : KEMINDCCA2Secure PK_KEM Unit SS Unit sorry)
    (_h_prf : PRFSecure CK MK Unit sorry) :
    ForwardSecure Adv_FS sorry ∧
    PostCompromiseSecure Adv_PCS sorry ∧
    PQPostCompromiseSecure Adv_PQPCS sorry := by
  sorry

end Cslib.Crypto.Signal

end -- section

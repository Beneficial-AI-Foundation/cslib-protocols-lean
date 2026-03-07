/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Protocols.Signal.PQXDH
public import Cslib.Crypto.Protocols.Signal.SPQR

/-!
# Protocol Composition: PQXDH + Triple Ratchet

## Background

A full Signal conversation consists of two phases:
1. **Session establishment** via PQXDH — produces a shared session key.
2. **Ongoing messaging** via the Double/Triple Ratchet (or SPQR) — uses
   the session key to initialize the ratchet state.

Proving end-to-end security requires a **composition theorem**: the security
of the composed protocol follows from the security of each component,
provided the interface between them is clean.

In practice, the PQXDH-to-Ratchet interface is somewhat famously not clean:
the session key from PQXDH becomes the initial root key of the ratchet,
and the security assumptions must align across protocol phases.

## Cryptographic model

**Axiomatic / stub.** This file states the composition theorem as a
proof obligation. The full proof requires formalizing the key composition
lemma and the security model for the composed protocol.

## Main definitions

- `Cslib.Crypto.Signal.ComposedSession` — a full Signal session state
- `Cslib.Crypto.Signal.EndToEndSecure` — end-to-end security of the composed protocol
- `Cslib.Crypto.Signal.composition_theorem` — PQXDH + Ratchet → end-to-end security

## References

- [Bhargavan et al., *Post-Quantum Signal*](https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf)
- [Cohn-Gordon et al., *On the Security of the Signal Protocol*](https://eprint.iacr.org/2016/1013.pdf)
-/

@[expose] public section

namespace Cslib.Crypto.Signal

/-- The state of a composed Signal session: PQXDH output + ratchet state. -/
structure ComposedSession (G Scalar RootKey CK MK PK_KEM SK_KEM SS Key CT : Type*) where
  /-- The PQXDH session key (used to initialize the ratchet). -/
  pqxdhOutput : PQXDHOutput Key CT
  /-- The SPQR ratchet state (initialized from the session key). -/
  ratchetState : SPQRState G Scalar RootKey CK MK PK_KEM SK_KEM SS

/-- End-to-end security of a composed Signal conversation.
    A conversation is secure if:
    1. Forward secrecy holds for all messages.
    2. Post-compromise security holds after DH ratchet steps.
    3. Post-quantum PCS holds after KEM ratchet steps.
    4. The session key from PQXDH is indistinguishable from random
       to any adversary that does not compromise both the DH and KEM
       components. -/
def EndToEndSecure
    (Adversary : Type*) (advantage : Advantage Adversary) : Prop :=
  Secure advantage

/-- Composition theorem (statement only): if PQXDH is AKE-secure and
    the Ratchet provides FS + PCS + PQ-PCS, then the composed protocol
    provides end-to-end security. -/
theorem composition_theorem
    {G PK_KEM Key : Type*}
    {Adv_SPQR Adv_E2E : Type*}
    (_h_pqxdh : PQXDHAKESecure G PK_KEM Key Unit sorry)
    (_h_spqr : SPQRSecure Adv_SPQR sorry) :
    EndToEndSecure Adv_E2E sorry := by
  sorry

end Cslib.Crypto.Signal

end -- section

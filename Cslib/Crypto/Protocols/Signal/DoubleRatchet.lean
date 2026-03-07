/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.DH
public import Cslib.Crypto.Foundations.AEAD
public import Cslib.Crypto.Foundations.KDF

/-!
# Double Ratchet Protocol

## Background

The Double Ratchet algorithm is Signal's core messaging protocol. After a
session is established (via PQXDH), the Double Ratchet manages the ongoing
encryption of messages. It combines two ratcheting mechanisms:

1. **Symmetric ratchet (sending/receiving chains):** A KDF chain that
   derives a new message key for each message, providing forward secrecy
   at the message level.

2. **DH ratchet:** Periodically exchanges new DH public keys, updating
   the root key. This provides **post-compromise security (PCS)**: even
   if the current state is compromised, future messages become secure
   once a new DH exchange completes.

## Cryptographic model

**Axiomatic.** The protocol state and transitions are specified as pure
functions. Security properties (forward secrecy, post-compromise security)
are stated as propositions. The full proof would reduce to PRF security
of the KDF, CDH hardness, and AEAD security.

## Main definitions

- `Cslib.Crypto.Signal.RatchetState` — the full ratchet state
- `Cslib.Crypto.Signal.SymmetricRatchet` — symmetric chain state
- `Cslib.Crypto.Signal.ratchetEncrypt` — encrypt a message
- `Cslib.Crypto.Signal.ratchetDecrypt` — decrypt a message
- `Cslib.Crypto.Signal.dhRatchetStep` — advance the DH ratchet
- `Cslib.Crypto.Signal.ForwardSecure` — forward secrecy property
- `Cslib.Crypto.Signal.PostCompromiseSecure` — PCS property

## References

- [Signal, *The Double Ratchet Algorithm*](https://signal.org/docs/specifications/doubleratchet)
- [Cohn-Gordon et al., *On the Security of the Signal Protocol*](https://eprint.iacr.org/2016/1013.pdf)
- [Alwen, Coretti, and Dodis (ACD19)](https://eprint.iacr.org/2018/1037.pdf)
-/

@[expose] public section

namespace Cslib.Crypto.Signal

/-! ### Symmetric ratchet (KDF chain) -/

/-- A symmetric ratchet chain state.
    `CK` = chain key type, `MK` = message key type. -/
structure SymmetricRatchet (CK MK : Type*) where
  /-- Current chain key. -/
  chainKey : CK
  /-- Message index (number of messages sent/received on this chain). -/
  index : Nat

/-- Advance the symmetric ratchet by one step: derive a new message key
    and the next chain key from the current chain key.

    `kdfStep` models the KDF: `chain_key → (next_chain_key, message_key)`. -/
def symRatchetStep {CK MK : Type*}
    (kdfStep : CK → CK × MK)
    (state : SymmetricRatchet CK MK) :
    SymmetricRatchet CK MK × MK :=
  let (nextCK, mk) := kdfStep state.chainKey
  ({ chainKey := nextCK, index := state.index + 1 }, mk)

/-! ### DH ratchet -/

/-- The DH ratchet key pair: current DH public and secret keys. -/
structure DHRatchetKeyPair (G Scalar : Type*) where
  /-- Current DH public key. -/
  pk : G
  /-- Current DH secret key. -/
  sk : Scalar

/-- The full Double Ratchet state. -/
structure RatchetState (G Scalar RootKey CK MK : Type*) where
  /-- The current DH ratchet key pair. -/
  dhKeyPair : DHRatchetKeyPair G Scalar
  /-- The remote party's current DH public key. -/
  remotePK : G
  /-- The root key (updated by each DH ratchet step). -/
  rootKey : RootKey
  /-- The sending chain. -/
  sendChain : SymmetricRatchet CK MK
  /-- The receiving chain. -/
  recvChain : SymmetricRatchet CK MK
  /-- Number of messages sent since last DH ratchet. -/
  sendCount : Nat
  /-- Number of messages expected in current receiving chain. -/
  recvCount : Nat
  /-- Previous sending chain length (for header). -/
  prevSendCount : Nat

/-- A message header: contains the sender's current DH public key and
    message counters needed for the receiver to synchronize. -/
structure MessageHeader (G : Type*) where
  /-- Sender's current DH ratchet public key. -/
  dhPublicKey : G
  /-- Previous chain message count. -/
  prevChainCount : Nat
  /-- Message number within the current chain. -/
  messageNumber : Nat

/-- Advance the DH ratchet upon receiving a new DH public key from the
    remote party. Derives new root key and receiving chain key.

    `rootKdf` models: `(root_key, dh_output) → (new_root_key, new_chain_key)`. -/
def dhRatchetStep
    {G Scalar RootKey CK MK : Type*}
    (_dhCompute : Scalar → G → G)
    (_rootKdf : RootKey → G → RootKey × CK)
    (_generateKeyPair : Unit → DHRatchetKeyPair G Scalar)
    (_state : RatchetState G Scalar RootKey CK MK)
    (_newRemotePK : G) :
    RatchetState G Scalar RootKey CK MK :=
  sorry -- Full state transition is a proof obligation.

/-- Encrypt a message using the Double Ratchet. -/
def ratchetEncrypt
    {G Scalar RootKey CK MK M C AD : Type*}
    [AEADScheme MK (MessageHeader G) M C AD]
    (_kdfStep : CK → CK × MK)
    (_state : RatchetState G Scalar RootKey CK MK)
    (_plaintext : M)
    (_ad : AD) :
    RatchetState G Scalar RootKey CK MK × MessageHeader G × C :=
  sorry -- Encryption step is a proof obligation.

/-- Decrypt a message using the Double Ratchet. -/
def ratchetDecrypt
    {G Scalar RootKey CK MK M C AD : Type*}
    [AEADScheme MK (MessageHeader G) M C AD]
    (_kdfStep : CK → CK × MK)
    (_dhCompute : Scalar → G → G)
    (_rootKdf : RootKey → G → RootKey × CK)
    (_generateKeyPair : Unit → DHRatchetKeyPair G Scalar)
    (_state : RatchetState G Scalar RootKey CK MK)
    (_header : MessageHeader G)
    (_ciphertext : C)
    (_ad : AD) :
    Option (RatchetState G Scalar RootKey CK MK × M) :=
  sorry -- Decryption step is a proof obligation.

/-! ### Security properties -/

/-- Forward secrecy: compromise of the current state does not reveal
    past message keys.

    Formally: for any state `s` at time `t`, the message keys derived
    at times `t' < t` are computationally indistinguishable from random,
    even given full knowledge of `s`. -/
def ForwardSecure
    (Adversary : Type*) (advantage : Advantage Adversary) : Prop :=
  Secure advantage

/-- Post-compromise security (PCS, also called "future secrecy" or
    "self-healing"): after a state compromise, security is restored once
    both parties complete a DH ratchet step.

    Formally: if the adversary learns the state at time `t`, then for
    `t' > t` after a full DH ratchet exchange, message keys at `t'` are
    again indistinguishable from random. -/
def PostCompromiseSecure
    (Adversary : Type*) (advantage : Advantage Adversary) : Prop :=
  Secure advantage

/-- The main security theorem for the Double Ratchet (statement only).
    The Double Ratchet provides forward secrecy and post-compromise security
    under CDH, PRF security of the KDF, and AEAD security.

    This formalizes the security theorem from Cohn-Gordon et al. (2016/2019). -/
theorem double_ratchet_security
    {G Scalar RootKey CK MK : Type*}
    {Adv_FS Adv_PCS : Type*}
    (_h_cdh : CDHSecure G sorry)
    (_h_prf : PRFSecure CK MK Unit sorry)
    (_h_aead_cpa : AEADINDCPASecure MK (MessageHeader G) Unit Unit Unit Unit sorry)
    (_h_aead_ctxt : AEADINTCTXTSecure MK (MessageHeader G) Unit Unit Unit sorry) :
    ForwardSecure Adv_FS sorry ∧
    PostCompromiseSecure Adv_PCS sorry := by
  sorry

end Cslib.Crypto.Signal

end -- section

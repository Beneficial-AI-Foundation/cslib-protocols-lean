/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.DH
public import Cslib.Crypto.Foundations.KEM
public import Cslib.Crypto.Foundations.KDF

/-!
# PQXDH: Post-Quantum Extended Diffie-Hellman Key Agreement

## Background

PQXDH is Signal's key agreement protocol that provides post-quantum forward
secrecy by combining classical Diffie-Hellman key exchanges with a
post-quantum KEM (ML-KEM / CRYSTALS-Kyber). It extends the X3DH protocol
with an additional KEM encapsulation.

The protocol involves two parties: Alice (initiator) and Bob (responder).
Bob publishes a set of prekeys. Alice uses these prekeys together with her
own ephemeral keys to establish a shared secret, which is then fed into
a KDF to produce the session key.

## Cryptographic model

**Axiomatic.** The protocol is specified as a sequence of operations on
abstract DH groups and KEM schemes. Security is stated as an
Authenticated Key Exchange (AKE) security game, with proof obligations
reducing to CDH hardness and KEM IND-CCA2 security.

The formalization follows the analysis in:
- Bhargavan et al., *Post-Quantum Signal*, USENIX Security 2024
- Hashimoto et al., ePrint 2025/040 and 2025/1090

## Main definitions

- `Cslib.Crypto.Signal.PQXDHParams` — protocol parameters
- `Cslib.Crypto.Signal.BobPreKeyBundle` — Bob's published prekeys
- `Cslib.Crypto.Signal.AliceEphemeral` — Alice's ephemeral state
- `Cslib.Crypto.Signal.PQXDHOutput` — protocol output (shared secret + metadata)
- `Cslib.Crypto.Signal.pqxdhInitiate` — Alice's side of the protocol
- `Cslib.Crypto.Signal.pqxdhRespond` — Bob's side of the protocol
- `Cslib.Crypto.Signal.AKEAdversary` — adversary for the AKE security game
- `Cslib.Crypto.Signal.PQXDHAKESecure` — AKE security of PQXDH

## References

- [Signal, *The PQXDH Key Agreement Protocol*](https://signal.org/docs/specifications/pqxdh/)
- [Bhargavan et al., *Post-Quantum Signal*](https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf)
- [Hashimoto et al., ePrint 2025/040](https://eprint.iacr.org/2025/040)
- [Hashimoto et al., ePrint 2025/1090](https://eprint.iacr.org/2025/1090)
-/

@[expose] public section

namespace Cslib.Crypto.Signal

/-! ### Protocol parameters -/

/-- PQXDH protocol parameters: a DH group and a KEM scheme.

    `G` = DH group element, `Scalar` = DH exponent,
    `PK_KEM` = KEM public key, `SK_KEM` = KEM secret key,
    `CT` = KEM ciphertext, `SS` = KEM shared secret,
    `R` = randomness, `Key` = derived session key. -/
structure PQXDHParams (G Scalar PK_KEM SK_KEM CT SS R Key : Type*) where
  /-- The DH group. -/
  dh : DHGroup G Scalar
  /-- The post-quantum KEM. -/
  kem : KEMScheme PK_KEM SK_KEM CT SS R
  /-- The KDF used to derive the final session key. -/
  kdf : KDF (List SS) Unit Unit Key

/-! ### Key bundles -/

/-- Bob's identity key (long-term DH key pair). -/
structure IdentityKey (G Scalar : Type*) where
  /-- Public identity key. -/
  pk : G
  /-- Secret identity key. -/
  sk : Scalar

/-- Bob's signed prekey (medium-term DH key pair, signed by identity key). -/
structure SignedPreKey (G Scalar : Type*) where
  /-- Public signed prekey. -/
  pk : G
  /-- Secret signed prekey. -/
  sk : Scalar

/-- Bob's one-time prekey (single-use DH key pair). -/
structure OneTimePreKey (G Scalar : Type*) where
  /-- Public one-time prekey. -/
  pk : G
  /-- Secret one-time prekey. -/
  sk : Scalar

/-- Bob's post-quantum prekey (KEM key pair). -/
structure PQPreKey (PK_KEM SK_KEM : Type*) where
  /-- KEM public key. -/
  pk : PK_KEM
  /-- KEM secret key. -/
  sk : SK_KEM

/-- Bob's published prekey bundle.
    Contains all public keys needed for Alice to initiate a session. -/
structure BobPreKeyBundle (G PK_KEM : Type*) where
  /-- Bob's public identity key. -/
  identityKey : G
  /-- Bob's public signed prekey. -/
  signedPreKey : G
  /-- Bob's one-time prekey (optional). -/
  oneTimePreKey : Option G
  /-- Bob's post-quantum prekey (KEM public key). -/
  pqPreKey : PK_KEM

/-! ### Protocol execution -/

/-- Alice's ephemeral state during PQXDH initiation. -/
structure AliceEphemeral (G Scalar : Type*) where
  /-- Alice's ephemeral DH key pair. -/
  ephemeralPK : G
  ephemeralSK : Scalar

/-- The output of the PQXDH protocol: shared secret and associated metadata. -/
structure PQXDHOutput (Key CT : Type*) where
  /-- The derived session key. -/
  sessionKey : Key
  /-- The KEM ciphertext (sent to Bob so he can decapsulate). -/
  kemCiphertext : CT

/-- Alice's side of the PQXDH protocol.

    Alice performs four DH exchanges and one KEM encapsulation:
    1. DH(IK_A, SPK_B)     — Alice's identity × Bob's signed prekey
    2. DH(EK_A, IK_B)      — Alice's ephemeral × Bob's identity
    3. DH(EK_A, SPK_B)     — Alice's ephemeral × Bob's signed prekey
    4. DH(EK_A, OPK_B)     — Alice's ephemeral × Bob's one-time prekey (optional)
    5. KEM.Encaps(PQPK_B)  — KEM encapsulation to Bob's PQ prekey

    The results are concatenated and fed into a KDF to produce the session key. -/
def pqxdhInitiate
    {G Scalar PK_KEM SK_KEM CT SS R Key : Type*}
    (_params : PQXDHParams G Scalar PK_KEM SK_KEM CT SS R Key)
    (_aliceIdentity : IdentityKey G Scalar)
    (_aliceEphemeral : AliceEphemeral G Scalar)
    (_bobBundle : BobPreKeyBundle G PK_KEM)
    (_kemRandomness : R) :
    PQXDHOutput Key CT :=
  sorry -- The full protocol computation is a proof obligation.

/-- Bob's side of the PQXDH protocol.

    Bob performs the same four DH exchanges (using his secret keys) and
    one KEM decapsulation, then derives the same session key. -/
def pqxdhRespond
    {G Scalar PK_KEM SK_KEM CT SS R Key : Type*}
    (_params : PQXDHParams G Scalar PK_KEM SK_KEM CT SS R Key)
    (_bobIdentity : IdentityKey G Scalar)
    (_bobSignedPreKey : SignedPreKey G Scalar)
    (_bobOneTimePreKey : Option (OneTimePreKey G Scalar))
    (_bobPQPreKey : PQPreKey PK_KEM SK_KEM)
    (_aliceIdentityPK : G)
    (_aliceEphemeralPK : G)
    (_kemCiphertext : CT) :
    Option Key :=
  sorry -- The full protocol computation is a proof obligation.

/-- Protocol agreement: if both sides execute honestly, they derive
    the same session key. -/
theorem pqxdh_agreement
    {G Scalar PK_KEM SK_KEM CT SS R Key : Type*}
    (params : PQXDHParams G Scalar PK_KEM SK_KEM CT SS R Key)
    (aliceIdentity : IdentityKey G Scalar)
    (aliceEphemeral : AliceEphemeral G Scalar)
    (bobIdentity : IdentityKey G Scalar)
    (bobSignedPreKey : SignedPreKey G Scalar)
    (bobOneTimePreKey : Option (OneTimePreKey G Scalar))
    (bobPQPreKey : PQPreKey PK_KEM SK_KEM)
    (kemRandomness : R) :
    let bobBundle : BobPreKeyBundle G PK_KEM := {
      identityKey := bobIdentity.pk
      signedPreKey := bobSignedPreKey.pk
      oneTimePreKey := bobOneTimePreKey.map (·.pk)
      pqPreKey := bobPQPreKey.pk
    }
    let aliceOut := pqxdhInitiate params aliceIdentity aliceEphemeral bobBundle kemRandomness
    let bobOut := pqxdhRespond params bobIdentity bobSignedPreKey bobOneTimePreKey
                    bobPQPreKey aliceIdentity.pk aliceEphemeral.ephemeralPK aliceOut.kemCiphertext
    bobOut = some aliceOut.sessionKey := by
  sorry

/-! ### AKE security -/

/-- Session identifier for the AKE security game. -/
structure SessionId where
  /-- Index identifying the session. -/
  idx : Nat

/-- An AKE (Authenticated Key Exchange) adversary for PQXDH.

    The adversary interacts with a challenger that manages multiple sessions.
    It can:
    - Initiate and respond to protocol sessions
    - Corrupt long-term keys
    - Reveal session keys
    - Test a challenge session (receives either the real key or a random one)

    The adversary wins if it correctly identifies the real session key. -/
structure AKEAdversary (G PK_KEM Key : Type*) (State : Type*) where
  /-- Interact with the challenger, making queries. Output state. -/
  interact : State
  /-- Given the challenge (real or random session key), output a bit. -/
  guess : Key → State → Bool

/-- AKE security of PQXDH: no efficient adversary can distinguish a real
    session key from a random one, even with access to corruption and
    reveal oracles, provided that the test session satisfies the freshness
    condition (not trivially compromised).

    The proof obligation reduces to:
    1. CDH hardness in the DH group
    2. IND-CCA2 security of the KEM
    3. PRF security of the KDF -/
def PQXDHAKESecure (G PK_KEM Key : Type*) (State : Type*)
    (advantage : Advantage (AKEAdversary G PK_KEM Key State)) : Prop :=
  Secure advantage

/-- The main security theorem for PQXDH (statement only).
    PQXDH is AKE-secure if the DH group satisfies CDH, the KEM is IND-CCA2
    secure, and the KDF is PRF-secure.

    This is the Lean formalization target for the computational proof in
    Bhargavan et al. (USENIX Security 2024). -/
theorem pqxdh_security
    {G Scalar PK_KEM SK_KEM CT SS R Key : Type*}
    {State_AKE State_CDH State_KEM State_PRF : Type*}
    (_params : PQXDHParams G Scalar PK_KEM SK_KEM CT SS R Key)
    (_h_cdh : CDHSecure G sorry)
    (_h_kem : KEMINDCCA2Secure PK_KEM CT SS State_KEM sorry)
    (_h_kdf : PRFSecure SS Key State_PRF sorry) :
    PQXDHAKESecure G PK_KEM Key State_AKE sorry := by
  sorry

end Cslib.Crypto.Signal

end -- section

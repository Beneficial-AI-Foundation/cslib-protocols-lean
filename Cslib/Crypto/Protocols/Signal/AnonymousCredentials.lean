/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.Advantage

/-!
# Anonymous Credentials and Private Group Messaging

## Background

Signal's private group system uses anonymous credentials to allow group
members to prove membership without revealing their identity. This enables
private group messaging where the server learns that a message comes from
a valid group member but not which member sent it.

The core cryptographic primitives are:
- **Anonymous credentials** — a credential scheme where the issuer signs
  attributes, and the holder can selectively disclose attributes while
  proving possession of a valid credential.
- **Group signatures** — signatures that prove membership in a group
  without revealing the signer's identity.
- **Zero-knowledge proofs** — used to prove statements about credentials
  without revealing the underlying data.

## Cryptographic model

**Axiomatic / stub.** This file defines the interfaces for anonymous
credentials and group membership proofs. Security properties (unforgeability,
anonymity, unlinkability) are stated as propositions.

This is a parallel track (Level X) to the main Signal protocol verification.

## Main definitions

- `Cslib.Crypto.Signal.AnonCredScheme` — anonymous credential scheme interface
- `Cslib.Crypto.Signal.GroupMembershipProof` — zero-knowledge proof of membership
- `Cslib.Crypto.Signal.AnonCredUnforgeable` — unforgeability
- `Cslib.Crypto.Signal.AnonCredAnonymous` — anonymity (unlinkability)

## References

- [Chase et al., *The Signal Private Group System*]
- [Camenisch and Lysyanskaya, *Signature Schemes and Anonymous Credentials*]
-/

@[expose] public section

namespace Cslib.Crypto.Signal

/-! ### Anonymous credential scheme -/

/-- An anonymous credential scheme.

    `IssuerPK` = issuer public key, `IssuerSK` = issuer secret key,
    `Credential` = issued credential, `Attribute` = credential attribute,
    `Presentation` = zero-knowledge presentation of a credential,
    `R` = randomness. -/
class AnonCredScheme (IssuerPK IssuerSK Credential Attribute Presentation R : Type*) where
  /-- Issue a credential for a set of attributes. -/
  issue : IssuerSK → List Attribute → R → Credential
  /-- Present a credential, selectively disclosing some attributes. -/
  present : Credential → List Bool → R → Presentation
  /-- Verify a presentation against the issuer's public key. -/
  verify : IssuerPK → Presentation → Bool

/-- A zero-knowledge proof of group membership.
    Proves that the presenter holds a valid credential issued by the
    group's issuer, without revealing which credential. -/
structure GroupMembershipProof (Presentation : Type*) where
  /-- The zero-knowledge presentation. -/
  presentation : Presentation
  /-- The group identifier. -/
  groupId : Nat

/-! ### Security properties -/

/-- Unforgeability: no efficient adversary can produce a valid presentation
    without holding a credential issued by the issuer. -/
def AnonCredUnforgeable (Presentation : Type*)
    (Adversary : Type*) (advantage : Advantage Adversary) : Prop :=
  Secure advantage

/-- Anonymity (unlinkability): no efficient adversary can link two
    presentations to the same credential holder. -/
def AnonCredAnonymous (Presentation : Type*)
    (Adversary : Type*) (advantage : Advantage Adversary) : Prop :=
  Secure advantage

/-- Full security of the anonymous credential scheme: unforgeable and
    anonymous. -/
def AnonCredSecure (Presentation : Type*)
    (Adv_Forge Adv_Anon : Type*)
    (advForge : Advantage Adv_Forge)
    (advAnon : Advantage Adv_Anon) : Prop :=
  AnonCredUnforgeable Presentation Adv_Forge advForge ∧
  AnonCredAnonymous Presentation Adv_Anon advAnon

end Cslib.Crypto.Signal

end -- section

/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.Advantage

/-!
# Key Encapsulation Mechanism (KEM) and IND-CCA2 Security

## Background

A Key Encapsulation Mechanism (KEM) is a triple of algorithms:
- **KeyGen**: generates a public/secret key pair.
- **Encaps**: given a public key, produces a ciphertext and a shared secret.
- **Decaps**: given a secret key and ciphertext, recovers the shared secret.

KEMs are the modern replacement for public-key encryption in hybrid
encryption schemes. The standard security notion is **IND-CCA2**: an
adversary with access to a decapsulation oracle cannot distinguish the
real shared secret from a random one.

## Cryptographic model

**Axiomatic.** We define the KEM interface and the IND-CCA2 security game
as structures. The advantage is an abstract function, and security is
stated as negligibility of the advantage. ML-KEM (CRYSTALS-Kyber) hardness
under MLWE would be stated as an axiom instantiating this framework.

## Main definitions

- `Cslib.Crypto.KEMScheme` — type class for KEM (KeyGen, Encaps, Decaps)
- `Cslib.Crypto.KEMCCAAdversary` — adversary for the IND-CCA2 game
- `Cslib.Crypto.KEMINDCCA2Secure` — IND-CCA2 security for KEMs

## References

- [NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf)
- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*, Ch. 12]
- [Signal, *The PQXDH Key Agreement Protocol*](https://signal.org/docs/specifications/pqxdh/)
-/

@[expose] public section

namespace Cslib.Crypto

/-- A Key Encapsulation Mechanism (KEM).

    `PK` = public key, `SK` = secret key, `CT` = ciphertext,
    `SS` = shared secret, `R` = randomness. -/
class KEMScheme (PK SK CT SS R : Type*) where
  /-- Key generation: randomness → (public key, secret key). -/
  keyGen : R → PK × SK
  /-- Encapsulation: public key → randomness → (ciphertext, shared secret). -/
  encaps : PK → R → CT × SS
  /-- Decapsulation: secret key → ciphertext → shared secret or failure. -/
  decaps : SK → CT → Option SS

/-- Correctness of a KEM: decapsulation recovers the encapsulated secret. -/
def KEMCorrect {PK SK CT SS R : Type*} [S : KEMScheme PK SK CT SS R] : Prop :=
  ∀ (r_key r_enc : R),
    let keys := S.keyGen r_key
    let result := S.encaps keys.1 r_enc
    S.decaps keys.2 result.1 = some result.2

/-! ### IND-CCA2 security game for KEMs -/

/-- An IND-CCA2 adversary for a KEM.
    The adversary sees a challenge ciphertext and must distinguish the real
    shared secret from a random one, with access to a decapsulation oracle
    (restricted: cannot query the challenge ciphertext). -/
structure KEMCCAAdversary (PK CT SS : Type*) (State : Type*) where
  /-- Phase 1: given public key and decapsulation oracle, produce state. -/
  setup : PK → (CT → Option SS) → State
  /-- Phase 2: given challenge ciphertext, candidate shared secret,
      restricted decapsulation oracle, and state, output a bit.
      `true` = adversary thinks the shared secret is real. -/
  distinguish : CT → SS → (CT → Option SS) → State → Bool

/-- IND-CCA2 security for a KEM: no efficient adversary can distinguish the
    real shared secret from a random one with non-negligible advantage. -/
def KEMINDCCA2Secure (PK CT SS : Type*) (State : Type*)
    (advantage : Advantage (KEMCCAAdversary PK CT SS State)) : Prop :=
  Secure advantage

/-! ### Public-key encryption as a special case -/

/-- A public-key encryption scheme.
    This is a KEM-like interface but encrypts/decrypts messages directly.

    `PK` = public key, `SK` = secret key, `M` = message (plaintext),
    `C` = ciphertext, `R` = randomness. -/
class PKEScheme (PK SK M C R : Type*) where
  /-- Key generation. -/
  keyGen : R → PK × SK
  /-- Encryption. -/
  enc    : PK → M → R → C
  /-- Decryption. -/
  dec    : SK → C → Option M

/-! ### IND-CPA adversary for PKE -/

/-- An IND-CPA adversary for a PKE scheme (passive, no decryption oracle). -/
structure CPAAdversary (PK M C : Type*) (State : Type*) where
  /-- Given the public key, produce two messages and some state. -/
  choose : PK → M × M × State
  /-- Given the challenge ciphertext and saved state, output a bit. -/
  guess  : C → State → Bool

/-! ### IND-CCA adversary for PKE -/

/-- An IND-CCA adversary for a PKE scheme (active, with decryption oracle). -/
structure CCAAdversary (PK M C : Type*) (State : Type*) where
  /-- Phase 1: given public key and decryption oracle, produce two messages and state. -/
  choose : PK → (C → Option M) → M × M × State
  /-- Phase 2: given challenge ciphertext, restricted decryption oracle, and state,
      output a bit. -/
  guess  : C → (C → Option M) → State → Bool

/-- IND-CPA security for a PKE scheme. -/
def INDCPASecure (PK M C : Type*) (State : Type*)
    (advantage : Advantage (CPAAdversary PK M C State)) : Prop :=
  Secure advantage

/-- IND-CCA security for a PKE scheme. -/
def INDCCASecure (PK M C : Type*) (State : Type*)
    (advantage : Advantage (CCAAdversary PK M C State)) : Prop :=
  Secure advantage

/-! ### CPA-to-CCA lifting -/

/-- Any CPA adversary can be lifted to a CCA adversary that ignores its oracle. -/
def cpaToCca {PK M C State : Type*} (A : CPAAdversary PK M C State)
    : CCAAdversary PK M C State where
  choose pk _oracle := A.choose pk
  guess c _oracle st := A.guess c st

/-- IND-CCA security implies IND-CPA security (for PKE schemes). -/
theorem ind_cca_implies_ind_cpa {PK M C State : Type*}
    (cpaAdv : Advantage (CPAAdversary PK M C State))
    (ccaAdv : Advantage (CCAAdversary PK M C State))
    (advantage_bound : ∀ (A : CPAAdversary PK M C State) (κ : Nat),
      cpaAdv.adv A κ ≤ ccaAdv.adv (cpaToCca A) κ)
    (denom_bound : ∀ (κ : Nat), ccaAdv.denom κ ≤ cpaAdv.denom κ)
    (h_cca : INDCCASecure PK M C State ccaAdv) :
    INDCPASecure PK M C State cpaAdv := by
  intro A c
  obtain ⟨κ₀, hκ⟩ := h_cca (cpaToCca A) c
  exact ⟨κ₀, fun κ hge => by
    calc cpaAdv.adv A κ * κ ^ c
        ≤ ccaAdv.adv (cpaToCca A) κ * κ ^ c :=
          Nat.mul_le_mul_right _ (advantage_bound A κ)
      _ ≤ ccaAdv.denom κ := hκ κ hge
      _ ≤ cpaAdv.denom κ := denom_bound κ⟩

end Cslib.Crypto

end -- section

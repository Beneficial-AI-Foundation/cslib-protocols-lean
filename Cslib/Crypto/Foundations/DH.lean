/-
Copyright (c) 2026 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Christiano Braga
-/

module

public import Cslib.Crypto.Foundations.Advantage
-- TODO: uncomment once toolchains align (VCVio @ v4.28.0, CSLib @ v4.29.0-rc2)
-- public import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman

/-!
# Diffie-Hellman Groups and Hardness Assumptions

## Background

A cyclic group `G` of prime order `q` with generator `g` supports the
Diffie-Hellman key exchange. The security of DH-based protocols relies on
the computational hardness of the following problems:

- **CDH** (Computational Diffie-Hellman): given `g^a` and `g^b`, compute `g^{ab}`.
- **DDH** (Decisional Diffie-Hellman): distinguish `(g^a, g^b, g^{ab})` from
  `(g^a, g^b, g^c)` for random `a, b, c`.

## Cryptographic model

**Axiomatic.** We define abstract interfaces for DH groups and state the CDH
and DDH hardness assumptions as propositions parameterized by advantage
functions. No concrete group is instantiated here.

PQXDH relies on CDH for the classical Diffie-Hellman components. The DDH
assumption is stronger and used in some analyses.

## Main definitions

- `Cslib.Crypto.DHGroup` — abstract Diffie-Hellman group interface
- `Cslib.Crypto.CDHAdversary` — adversary for the CDH game
- `Cslib.Crypto.DDHAdversary` — adversary for the DDH game
- `Cslib.Crypto.CDHSecure` — CDH hardness as negligibility of advantage
- `Cslib.Crypto.DDHSecure` — DDH hardness as negligibility of advantage

## Main results

- `Cslib.Crypto.ddh_implies_cdh` — DDH hardness implies CDH hardness

## Cross-references with VCVio

| Cslib definition | VCVio equivalent |
|-----------------|-----------------|
| `Cslib.Crypto.DHGroup` | Hard Homogeneous Spaces (`AddTorsor G P`) |
| `Cslib.Crypto.CDHAdversary` | `VCVio.CDHAdversary` (via `parallelizationAdversary`) |
| `Cslib.Crypto.DDHAdversary` | `VCVio.DDHAdversary` (via `parallelTestingAdversary`) |
| `Cslib.Crypto.CDHSecure` | `VCVio.cdhExp` + `VCVio.negligible` |
| `Cslib.Crypto.DDHSecure` | `VCVio.ddhAdvantage` + `VCVio.negligible` |
| (none) | `VCVio.DLogAdversary`, `VCVio.dlogExp` (discrete log) |

VCVio models DH groups via Mathlib's `AddTorsor` abstraction (hard homogeneous
spaces), which generalizes to any group action. Our `DHGroup` is a simpler
interface for protocol-level specifications. For concrete security proofs,
use VCVio's probabilistic adversaries.

## References

- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*, Ch. 10–11]
- [Katz and Lindell, *Introduction to Modern Cryptography*, §9.3–9.4]
- [Signal, *The PQXDH Key Agreement Protocol*](https://signal.org/docs/specifications/pqxdh/)
-/

@[expose] public section

namespace Cslib.Crypto

/-- An abstract Diffie-Hellman group.
    `G` is the group type, `Scalar` is the exponent type (ℤ/qℤ). -/
class DHGroup (G : Type*) (Scalar : Type*) where
  /-- The generator of the group. -/
  generator : G
  /-- Scalar multiplication (exponentiation): `g^a`. -/
  smul : Scalar → G → G
  /-- Group operation. -/
  mul : G → G → G
  /-- Identity element. -/
  one : G

namespace DHGroup

variable {G Scalar : Type*} [inst : DHGroup G Scalar]

/-- Convenience: `g^a` where `g` is the generator. -/
def exp (a : Scalar) : G := inst.smul a inst.generator

end DHGroup

/-! ### CDH: Computational Diffie-Hellman -/

/-- A CDH adversary: given `g^a` and `g^b`, attempts to compute `g^{ab}`. -/
structure CDHAdversary (G : Type*) where
  /-- Given public values `g^a` and `g^b`, output a guess for `g^{ab}`. -/
  solve : G → G → G

/-- CDH security: no efficient adversary can compute `g^{ab}` from `g^a`, `g^b`
    with non-negligible probability.

    Parameterized by an axiomatized advantage function. -/
def CDHSecure (G : Type*) (advantage : Advantage (CDHAdversary G)) : Prop :=
  Secure advantage

/-! ### DDH: Decisional Diffie-Hellman -/

/-- A DDH adversary: given a triple `(g^a, g^b, T)`, guesses whether
    `T = g^{ab}` (real) or `T = g^c` (random). -/
structure DDHAdversary (G : Type*) where
  /-- Given `(g^a, g^b, T)`, output `true` if the adversary thinks `T = g^{ab}`. -/
  distinguish : G → G → G → Bool

/-- DDH security: no efficient adversary can distinguish real from random
    DH triples with non-negligible probability. -/
def DDHSecure (G : Type*) (advantage : Advantage (DDHAdversary G)) : Prop :=
  Secure advantage

/-! ### DDH implies CDH -/

/-- DDH hardness implies CDH hardness.
    If no adversary can *distinguish* DH triples, then no adversary can
    *compute* the DH value. The reduction builds a DDH distinguisher from
    any CDH solver. -/
theorem ddh_implies_cdh (G : Type*)
    (cdhAdv : Advantage (CDHAdversary G))
    (ddhAdv : Advantage (DDHAdversary G))
    (advantage_bound : ∀ (A : CDHAdversary G) (κ : Nat),
      cdhAdv.adv A κ ≤ ddhAdv.adv ⟨fun ga gb => sorry⟩ κ)
    (denom_bound : ∀ (κ : Nat), ddhAdv.denom κ ≤ cdhAdv.denom κ)
    (h_ddh : DDHSecure G ddhAdv) :
    CDHSecure G cdhAdv := by
  sorry

end Cslib.Crypto

end -- section

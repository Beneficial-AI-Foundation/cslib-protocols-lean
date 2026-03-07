# Cslib.Crypto — Formal Verification of Signal's Cryptographic Protocols

This subtree formalizes the cryptographic primitives and protocols used by
[Signal](https://signal.org/), from low-level building blocks (KEM, DH, AEAD,
KDF) through the full protocol stack (PQXDH, Double Ratchet, Triple Ratchet,
SPQR) to protocol composition and implementation correctness.

## Cryptographic model

The formalization uses an **axiomatic** approach (approach #1 in the taxonomy
below). The key design choices are:

| Aspect | Choice |
|--------|--------|
| **Advantage** | Abstract function `Adversary → ℕ → ℕ` (numerator + denominator) |
| **Negligibility** | Cross-multiplied: `f(κ) · κᶜ ≤ 1` over ℕ (avoids ℝ / Mathlib) |
| **Hardness assumptions** | Stated as axioms (CDH, DDH, MLWE, PRF security) |
| **Security reductions** | Proved symbolically via advantage bounds |
| **Probability** | Not modeled directly — advantage is axiomatized |
| **Adversaries** | Deterministic structures (no probabilistic monad) |

This is a **symbolic / axiomatic** model, not a probabilistic one. It mirrors
how pen-and-paper cryptographic proofs work: hardness assumptions are axioms,
and security reductions compose advantage bounds. The model is sound for
stating and connecting security properties, but does not compute concrete
advantage values or model probabilistic adversaries.

### Alternative approaches (not yet implemented)

1. **Axiomatized advantage** — current implementation
2. **Lightweight PMF monad** — composable probability over `Fintype` (requires Mathlib's `PMF`)
3. **CryptHOL/SSProve-style framework** — full game-based proofs with oracles (no Lean 4 framework exists yet)

## File structure

### Level −1: Cryptographic Infrastructure (`Foundations/`)

Abstract interfaces for cryptographic primitives and their security games.

| File | Contents | Formalization status |
|------|----------|---------------------|
| `Negligible.lean` | Negligible functions over ℕ | **Defined.** `negligible_zero` proved. `negligible_add`, `negligible_mul_poly` are `sorry`. |
| `Advantage.lean` | Advantage framework (`Advantage`, `Secure`) | **Defined.** No `sorry`. |
| `DH.lean` | DH group interface, CDH/DDH adversaries and security | **Defined.** `ddh_implies_cdh` is `sorry`. |
| `KEM.lean` | KEM interface (`KEMScheme`), IND-CCA2 game, PKE scheme, IND-CPA/CCA, `cpaToCca`, `ind_cca_implies_ind_cpa` | **Defined.** `ind_cca_implies_ind_cpa` **proved**. |
| `AEAD.lean` | AEAD interface, IND-CPA and INT-CTXT games | **Defined.** No proofs needed (game definitions only). |
| `KDF.lean` | KDF and PRF interfaces, PRF security game, Dual-PRF | **Defined.** No proofs needed (game definitions only). |

### Level 0: PQXDH (`Protocols/Signal/PQXDH.lean`)

Post-Quantum Extended Diffie-Hellman key agreement protocol.

| Definition | Status |
|-----------|--------|
| `PQXDHParams`, key bundles, `BobPreKeyBundle` | **Defined** |
| `pqxdhInitiate`, `pqxdhRespond` | **Stub** (`sorry`) — protocol computation is a proof obligation |
| `pqxdh_agreement` (correctness) | **Stated** (`sorry`) |
| `AKEAdversary`, `PQXDHAKESecure` | **Defined** |
| `pqxdh_security` (CDH + KEM + KDF → AKE) | **Stated** (`sorry`) |

**References:** [Signal PQXDH spec](https://signal.org/docs/specifications/pqxdh/),
[Bhargavan et al. USENIX 2024](https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf),
[ePrint 2025/040](https://eprint.iacr.org/2025/040),
[ePrint 2025/1090](https://eprint.iacr.org/2025/1090)

### Level 1: Double Ratchet (`Protocols/Signal/DoubleRatchet.lean`)

Signal's core ongoing messaging protocol with symmetric and DH ratchets.

| Definition | Status |
|-----------|--------|
| `SymmetricRatchet`, `symRatchetStep` | **Defined** (functional) |
| `RatchetState`, `MessageHeader` | **Defined** |
| `dhRatchetStep`, `ratchetEncrypt`, `ratchetDecrypt` | **Stub** (`sorry`) |
| `ForwardSecure`, `PostCompromiseSecure` | **Defined** |
| `double_ratchet_security` (CDH + PRF + AEAD → FS ∧ PCS) | **Stated** (`sorry`) |

**References:** [Signal Double Ratchet spec](https://signal.org/docs/specifications/doubleratchet),
[Cohn-Gordon et al.](https://eprint.iacr.org/2016/1013.pdf),
[ACD19](https://eprint.iacr.org/2018/1037.pdf)

### Level 2: Triple Ratchet and SPQR

#### `Protocols/Signal/MLKEMBraid.lean`

| Definition | Status |
|-----------|--------|
| `BraidState`, `braidEncaps`, `braidDecaps` | **Stub** (`sorry`) |
| `BraidINDCCA2Secure`, `braid_security` | **Stated** (`sorry`) |

**References:** [Signal ML-KEM Braid spec](https://signal.org/docs/specifications/mlkembraid/),
[NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf)

#### `Protocols/Signal/TripleRatchet.lean`

| Definition | Status |
|-----------|--------|
| `TripleRatchetState` | **Defined** (extends `RatchetState` + `BraidState`) |
| `tripleRatchetEncrypt`, `tripleRatchetDecrypt` | **Stub** (`sorry`) |
| `PQPostCompromiseSecure` | **Defined** |
| `triple_ratchet_security` (CDH + KEM + PRF → FS ∧ PCS ∧ PQ-PCS) | **Stated** (`sorry`) |

**References:** [Bienstock et al.](https://eprint.iacr.org/2025/078.pdf)

#### `Protocols/Signal/SPQR.lean`

| Definition | Status |
|-----------|--------|
| `SPQRState` (wraps `TripleRatchetState` + scheduling) | **Defined** |
| `spqrEncrypt`, `spqrDecrypt` | **Stub** (`sorry`) |
| `SPQRSecure`, `spqr_security` | **Stated** (`sorry`) |

**References:** [Balli et al.](https://eprint.iacr.org/2025/2267.pdf),
[Signal blog](https://signal.org/blog/spqr/),
[PQShield analysis](https://pqshield.com/diving-into-signals-new-pq-protocol/)

### Level 3: Implementation Correctness (`Protocols/Bridge/ImplCorrectness.lean`)

| Definition | Status |
|-----------|--------|
| `FunctionallyCorrect` (generic correctness predicate) | **Defined** |
| `KEMImplCorrect`, `AEADImplCorrect` | **Defined** (proof structures) |
| `impl_correct_preserves_security` | **Stated** (`sorry`) |

This level targets the Aeneas/Charon pipeline: Rust → Lean extraction → equational proof.

### Level 4: Protocol Composition (`Protocols/Signal/Composition.lean`)

| Definition | Status |
|-----------|--------|
| `ComposedSession` (PQXDH output + SPQR state) | **Defined** |
| `EndToEndSecure` | **Defined** |
| `composition_theorem` (PQXDH + SPQR → E2E) | **Stated** (`sorry`) |

### Level X: Anonymous Credentials (`Protocols/Signal/AnonymousCredentials.lean`)

| Definition | Status |
|-----------|--------|
| `AnonCredScheme` (issue, present, verify) | **Defined** |
| `GroupMembershipProof` | **Defined** |
| `AnonCredUnforgeable`, `AnonCredAnonymous`, `AnonCredSecure` | **Defined** |

## What has been formalized

### Fully proved
- `Cslib.Crypto.negligible_zero` — the zero function is negligible
- `Cslib.Crypto.ind_cca_implies_ind_cpa` — IND-CCA security implies IND-CPA security (for PKE)

### Defined (types, interfaces, security games)
- All cryptographic primitive interfaces (KEM, DH, AEAD, KDF, PRF)
- All security game structures (IND-CCA2, CDH, DDH, PRF, IND-CPA, INT-CTXT)
- All protocol state types and message formats
- All security property definitions (FS, PCS, PQ-PCS, AKE, E2E)

### Stated but not proved (`sorry`)
- Protocol computations (PQXDH initiate/respond, ratchet encrypt/decrypt)
- Security reduction theorems (PQXDH, Double Ratchet, Triple Ratchet, SPQR)
- Composition theorem
- Negligible function closure properties (addition, polynomial multiplication)
- DDH → CDH reduction
- Implementation correctness bridge

## Dependency graph

```
Negligible ← Advantage ← DH ← PQXDH ← Composition
                        ↑ KEM ← MLKEMBraid ← TripleRatchet ← SPQR ← Composition
                        ↑ AEAD ← DoubleRatchet ← TripleRatchet
                        ↑ KDF ← PQXDH, DoubleRatchet
                        ↑ KEM, AEAD, KDF ← ImplCorrectness
                        ↑ Advantage ← AnonymousCredentials
```

## References

### Textbooks
- [Boneh, Shoup — *A Graduate Course in Applied Cryptography*](https://toc.cryptobook.us/)
- [Rosulek — *The Joy of Cryptography*](https://joyofcryptography.com/)
- [Katz, Lindell — *Introduction to Modern Cryptography*](https://www.cs.umd.edu/~jkatz/imc.html)

### Signal specifications
- [PQXDH](https://signal.org/docs/specifications/pqxdh/)
- [Double Ratchet](https://signal.org/docs/specifications/doubleratchet)
- [ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/)
- [SPQR blog](https://signal.org/blog/spqr/)

### Papers
- [Bhargavan et al., *Post-Quantum Signal* (USENIX 2024)](https://www.usenix.org/system/files/usenixsecurity24-bhargavan.pdf)
- [Cohn-Gordon et al., *On the Security of the Signal Protocol*](https://eprint.iacr.org/2016/1013.pdf)
- [Alwen, Coretti, Dodis (ACD19)](https://eprint.iacr.org/2018/1037.pdf)
- [Bienstock et al., *Triple Ratchet*](https://eprint.iacr.org/2025/078.pdf)
- [Balli et al., *SPQR*](https://eprint.iacr.org/2025/2267.pdf)
- [Hashimoto et al., ePrint 2025/040](https://eprint.iacr.org/2025/040)
- [Hashimoto et al., ePrint 2025/1090](https://eprint.iacr.org/2025/1090)
- [NIST FIPS 203 (ML-KEM)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf)

### Tools
- [Aeneas](https://github.com/AeneasVerif/aeneas) — Rust → Lean translation
- [Charon](https://github.com/AeneasVerif/charon) — Rust MIR extraction
- [PQXDH CryptoVerif proofs](https://github.com/Inria-Prosecco/pqxdh-analysis)

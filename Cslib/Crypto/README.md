# CSLib Cryptography Library

Formalization of definitions and theorems from
**A Graduate Course in Applied Cryptography** by Dan Boneh and Victor Shoup
(Version 0.6, January 2023).

Book URL: <https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_6.pdf>

## File-by-file map to the book

Each file formalizes specific definitions, attack games, and theorems from the
book. Below we list the mathematical content and how it is formalized.

### Foundations

#### `Foundations/Negligible.lean` — Section 2.3.1

| Book | Lean | Notes |
|------|------|-------|
| **Definition 2.5** (Negligible). A function `f : ℤ≥₁ → ℝ` is *negligible* if for every `c > 0` there exists `n₀` such that `\|f(n)\| < 1/nᶜ` for all `n ≥ n₀`. | `Negligible f` := `Asymptotics.SuperpolynomialDecay atTop (↑·) f`, i.e., `∀ k : ℕ, Tendsto (fun n => n^k * f n) atTop (nhds 0)`. | Uses Mathlib's filter-based formulation; equivalence stated as `negligible_iff_forall_pow_tendsto_zero`. |
| **Definition 2.6** (Super-poly). `f` is super-poly if `1/f` is negligible. | `SuperPoly f` := `Negligible (fun n => 1 / f n)`. | Direct transcription. |
| **Definition 2.7** (Poly-bounded). `\|f(n)\| ≤ nᶜ + d` for some `c, d`. | `PolyBounded f` := `∃ (c : ℕ) (d : ℝ), d ≥ 0 ∧ ∀ n, \|f n\| ≤ n^c + d`. | Exponent restricted to `ℕ` (see Design Choices). |
| **Fact 2.6(i)** (Sum of negligibles is negligible). | `Negligible.add'` — proved via `SuperpolynomialDecay.add`. | |
| **Fact 2.6(ii)** (Poly-bounded closure). | `PolyBounded.add`, `PolyBounded.mul` — `sorry`. | |
| **Fact 2.6(iii)** (Poly-bounded × negligible = negligible). | `PolyBounded.mul_negligible` — `sorry`. | |

#### `Foundations/Advantage.lean` — Sections 2.2.2, 2.2.5

| Book | Lean | Notes |
|------|------|-------|
| **Section 2.2.5.1**. `Xadv[A,S] := \|Pr[W₀] - Pr[W₁]\|`. | `Advantage p₀ p₁ := \|p₀ - p₁\|`. | |
| **Section 2.2.5**. Bit-guessing advantage `Xadv*[A,S] := \|Pr[W] - 1/2\|`. | `BitGuessingAdvantage pWin := \|pWin - 1/2\|`. | |
| **Theorem 2.10**. `Xadv = 2 · Xadv*`. | `advantage_eq_two_mul_bitGuessing` — **proved**. | |

### Secret Key Encryption

#### `SecretKey/Encryption/ShannonCipher.lean` — Sections 2.1.1–2.1.3

| Book | Lean | Notes |
|------|------|-------|
| **Definition 2.1**. A cipher `E = (E, D)` over `(K, M, C)` with `D(k, E(k, m)) = m`. | `ShannonCipher Key Msg Ctxt` with fields `encrypt`, `decrypt`, `correct`. | |
| **Definition 2.1** (Perfect security). `∀ m₀ m₁ c, Pr_k[E(k,m₀)=c] = Pr_k[E(k,m₁)=c]`. | `PerfectlySecure E` := for all `m₀ m₁ c`, `\|{k : E(k,m₀)=c}\| = \|{k : E(k,m₁)=c}\|`. | Uses counting formulation (Theorem 2.1(ii)), equivalent over uniform finite key space. |
| **Example 2.1** (One-time pad). `E(k,m) = k ⊕ m`, `D(k,c) = k ⊕ c`. | `otp n` using `BitVec n` XOR. Correctness **proved**. | |
| **Theorem 2.2** (OTP is perfectly secure). | `otp_perfectlySecure` — `sorry`. | |
| **Theorem 2.5** (Shannon's theorem). `\|K\| ≥ \|M\|`. | `perfectlySecure_card_key_ge_card_msg` — `sorry`. | |
| **Example 2.4** (Additive OTP mod n). | `additiveOtp n` using `ZMod n`. Correctness **proved**. | |

#### `SecretKey/Encryption/ComputationalCipher.lean` — Sections 2.2.1, 2.3.2

| Book | Lean | Notes |
|------|------|-------|
| **Section 2.2.1**. Computational cipher over `(K,M,C)`. | `Cipher Key Msg Ctxt` (abbrev for `ShannonCipher`). | |
| **Definition 2.10**. Cipher family indexed by security parameter `λ` (and system parameter `Λ`). | `CipherFamily` with `Key Msg Ctxt : ℕ → Type*`, `encrypt`, `decrypt`, `correct`. | System parameter `Λ` omitted (see Design Choices). |

#### `SecretKey/Encryption/SemanticSecurity.lean` — Sections 2.2.2, 2.2.5

| Book | Lean | Notes |
|------|------|-------|
| **Attack Game 2.1**. Adversary submits `(m₀,m₁)`, receives `E(k, m_b)`, outputs `b̂`. | `SSAdversary E` with `chooseMessages` and `distinguish`. | |
| **Definition 2.2**. `SSadv[A,E] := \|Pr[W₀] - Pr[W₁]\|` is negligible. | `SSAdvantage`, `CipherFamily.SemanticallySecure`. | |
| **Theorem 2.10** (instantiated). `SSadv = 2 · SSadv*`. | `SSAdvantage_eq_two_mul_bitGuessing` — **proved**. | |
| **Attack Game 2.2** (Message recovery). | `MRAdversary`, `MRAdvantage`. | |
| **Theorem 2.7** (SS ⟹ MR security). | `secure_against_message_recovery` — `sorry`. | |

### Stream Ciphers

#### `SecretKey/StreamCipher/PRG.lean` — Sections 3.1–3.2

| Book | Lean | Notes |
|------|------|-------|
| **Definition 3.1**. PRG `G : S → R` with `\|R\| > \|S\|`. | `PRGFamily` with `Seed`, `Output`, `generate`, `expansion`. | |
| **Attack Game 3.1**. Distinguish `G(s)` from random `r`. | `PRGAdversary`, `PRGAdvantage`. | |
| **Definition 3.1** (PRG security). Advantage is negligible. | `PRGFamily.Secure`. | |
| **Section 3.2**. Stream cipher: `E(k,m) = G(k) ⊕ m`. | `streamCipher seedLen msgLen G`. Correctness **proved**. | |

### Block Ciphers

#### `SecretKey/BlockCipher/Basic.lean` — Section 4.1

| Book | Lean | Notes |
|------|------|-------|
| **Section 4.1**. Block cipher `E(k,·)` is a permutation on block space `X`. | `BlockCipherFamily` with `perm : ∀ sp, Key sp → Equiv.Perm (Block sp)`. | Uses Mathlib's `Equiv.Perm`. |
| Encrypt/decrypt and correctness. | `encrypt`, `decrypt`, `correct` — correctness **proved** via `symm_apply_apply`. | |
| Block cipher → generic cipher. | `toCipherFamily`. | |
| **Attack Game 4.1**. Distinguish `E(k,·)` from random permutation. | `BCAdversary`, `BCAdvantage`. | |
| **Section 4.1** (Security). Advantage is negligible. | `BlockCipherFamily.Secure`. | |

#### `SecretKey/BlockCipher/PRF.lean` — Section 4.4

| Book | Lean | Notes |
|------|------|-------|
| **Section 4.4.1**. PRF `F(k,·) : X → Y`. | `PRFFamily` with `eval : ∀ sp, Key sp → Domain sp → Range sp`. | |
| **Section 4.4.1** (PRF security). Distinguish from random function. | `PRFAdversary`, `PRFAdvantage`, `PRFFamily.Secure`. | |
| Block cipher → PRF (since `E(k,·)` is a function `X → X`). | `BlockCipherFamily.toPRFFamily`. | |

### Scaffolding (TODO) files

| File | Book chapters | Structures defined |
|------|---------------|-------------------|
| `SecretKey/CPA.lean` | Ch. 5 | — |
| `SecretKey/MAC/Basic.lean` | Ch. 6 | `MACFamily` |
| `SecretKey/UHF.lean` | Ch. 7 | — |
| `SecretKey/CRH.lean` | Ch. 8 | `CRHFamily` |
| `SecretKey/AE.lean` | Ch. 9 | — |
| `PublicKey/Tools.lean` | Ch. 10 | — |
| `PublicKey/Encryption.lean` | Ch. 11–12 | `PKEFamily` |
| `PublicKey/Signature.lean` | Ch. 13–14 | `SignatureFamily` |
| `PublicKey/EllipticCurve.lean` | Ch. 15 | — |
| `PublicKey/Lattice.lean` | Ch. 16–17 | — |
| `Protocols/Identification.lean` | Ch. 18 | — |
| `Protocols/ZeroKnowledge.lean` | Ch. 19–20 | — |
| `Protocols/KeyExchange.lean` | Ch. 21 | — |
| `Protocols/Threshold.lean` | Ch. 22 | — |
| `Protocols/MPC.lean` | Ch. 23 | — |

### Test files (`CslibTests/Crypto/`)

| File | Concepts exercised |
|------|--------------------|
| `Foundations.lean` | Zero/constant negligible functions, advantage symmetry, bit-guessing computation, Theorem 2.10 instantiation |
| `ShannonCipher.lean` | OTP (BitVec 8) correctness and computation, additive OTP (ZMod 26), substitution cipher (Equiv.Perm), Fin 2 cipher |
| `ComputationalCipher.lean` | Cipher family over ZMod, trivial adversary with zero advantage |
| `BlockCipher.lean` | Tiny block cipher (Fin 4), cipher family conversion, PRF conversion |
| `PRG.lean` | Toy PRG via concatenation, stream cipher correctness |

## Design choices

### 1. Negligible functions via `SuperpolynomialDecay`
The book defines negligible as: for all `c > 0`, eventually `|f(n)| < 1/nᶜ`.
We use Mathlib's `Asymptotics.SuperpolynomialDecay`, which is equivalent:
`∀ k : ℕ, Tendsto (fun n => n^k * f n) atTop (nhds 0)`.
This gives us access to Mathlib's existing lemmas (e.g., `add`, `mul`) for free.

### 2. Counting formulation for perfect security
The book's Definition 2.1 uses probabilities: `Pr_k[E(k,m₀)=c] = Pr_k[E(k,m₁)=c]`.
We use the equivalent counting formulation: `|{k : E(k,m₀)=c}| = |{k : E(k,m₁)=c}|`.
Over a finite uniform key space, these are identical since
`Pr_k[E(k,m)=c] = |{k : E(k,m)=c}| / |K|`. This avoids measure-theoretic machinery.

### 3. Advantage via finite counting
All advantage definitions (SS, PRG, BC, PRF) compute probabilities as
`|{x ∈ S : P(x)}| / |S|` using `Finset.univ.filter` and `Fintype.card`.
This is exact over finite types and avoids probability monads.

### 4. Deterministic encryption only
The book allows probabilistic encryption in Section 2.2.1.
We formalize only deterministic ciphers (`E : K → M → C`).
Probabilistic encryption can be modeled by incorporating randomness into the key
or by using `PMF` (Probability Mass Function from Mathlib) in future work.

### 5. No system parameter `Λ`
The book's Definition 2.10 parameterizes cipher families by both a security
parameter `λ` and a system parameter `Λ`. We index only by `λ : ℕ`,
which suffices for the core definitions and all examples in the book.

### 6. Natural exponents in `PolyBounded`
The book's Definition 2.7 uses real exponents `c ∈ ℝ`. We restrict to
`c : ℕ`, which avoids `rpow` (real exponentiation) complexities and suffices
since any real-exponent polynomial bound can be rounded up to a natural one.

### 7. Security parameter named `sp`
Lean 4 reserves `λ` as a keyword (anonymous function). We use `sp` throughout
instead. Docstrings still refer to `λ` for consistency with the book.

### 8. `BitVec.instFintype`
Lean 4 / Mathlib does not currently provide `Fintype (BitVec n)`.
We define it in `ShannonCipher.lean` via the equivalence `BitVec n ≃ Fin (2^n)`.

### 9. `DecidableEq` fields on block/domain types
`Fintype (Equiv.Perm α)` and `Fintype (α → β)` require `DecidableEq α`.
We add `block_deceq` to `BlockCipherFamily` and `domain_deceq` to `PRFFamily`
to enable these instances for security definitions.

## Limitations

### Incomplete proofs (`sorry`)
The following theorems are stated but not yet proved:
- `otp_perfectlySecure` — OTP perfect security (Theorem 2.2)
- `additiveOtp_perfectlySecure` — Additive OTP perfect security
- `perfectlySecure_card_key_ge_card_msg` — Shannon's theorem (Theorem 2.5)
- `PolyBounded.add`, `PolyBounded.mul` — Poly-bounded closure (Fact 2.6(ii))
- `PolyBounded.mul_negligible` — Poly-bounded × negligible (Fact 2.6(iii))
- `secure_against_message_recovery` — SS ⟹ MR security (Theorem 2.7)

### No computational complexity model
The book's security definitions quantify over "efficient" (PPT) adversaries.
We quantify over *all* adversaries, making our definitions information-theoretic
rather than computational. Adding a PPT restriction requires a complexity model
that does not yet exist in Mathlib/CSLib.

### Coverage
Chapters 2–4 are formalized with definitions, adversary models, and security
notions. Chapters 5–23 have scaffolding (structures for MACs, CRH, PKE,
signatures) with TODO items for future formalization.

## What has not been implemented yet

Below is a chapter-by-chapter list of what remains unformalized, grouped by
the reason it is not yet implemented.

### Chapters with partial formalization (2–4)

| Chapter | Missing content | Reason |
|---------|----------------|--------|
| **Ch. 2** (Encryption) | Probabilistic encryption (Section 2.2.1 general case) | Our ciphers are deterministic (`E : K → M → C`). Probabilistic encryption requires a `PMF` monad or explicit randomness type not yet integrated. |
| **Ch. 2** (Encryption) | Multi-key semantic security (Attack Game 2.4) | Requires a stateful, multi-query adversary model we have not built. |
| **Ch. 3** (Stream ciphers) | Security proof: PRG security ⟹ stream cipher semantic security (Theorem 3.1) | Requires connecting PRG advantage to SS advantage via a reduction argument; the counting-based probability framework does not yet support hybrid arguments. |
| **Ch. 3** (Stream ciphers) | Composition theorems for PRGs (Sections 3.4–3.5) | Parallel and sequential composition need multi-step game-hopping proofs. |
| **Ch. 4** (Block ciphers) | PRP/PRF switching lemma (Theorem 4.4) | Requires a birthday-bound probability argument not yet formalized. |
| **Ch. 4** (Block ciphers) | Concrete block cipher constructions (AES, DES) | Out of scope: these are implementation-level algorithms, not definitional. |

### Chapters with scaffolding only (5–9: secret-key constructions)

| Chapter | File | What exists | What is missing | Reason |
|---------|------|-------------|-----------------|--------|
| **Ch. 5** (CPA security) | `SecretKey/CPA.lean` | Empty scaffolding | CPA attack game, CPA-secure encryption, randomized counter mode, CBC mode | CPA requires a *stateful, multi-query* adversary that makes encryption oracle queries. Our current adversary model is single-query. Building an oracle/interaction framework is a prerequisite. |
| **Ch. 6** (MACs) | `SecretKey/MAC/Basic.lean` | `MACFamily` structure with `sign`, `verify`, `correct` | MAC security game (existential forgery), PRF-based MACs, CBC-MAC, CMAC, PMAC | The forgery game requires a multi-query signing oracle. Same oracle framework blocker as Ch. 5. |
| **Ch. 7** (UHFs) | `SecretKey/UHF.lean` | Empty scaffolding | Universal hash families, ε-almost universal, UHF-based MACs, poly hash | Definitions are straightforward but depend on Ch. 6 MAC security to be useful. |
| **Ch. 8** (CRH) | `SecretKey/CRH.lean` | `CRHFamily` structure with `hash`, `compressing` | Collision resistance game, birthday attack bound, Merkle-Damgård, Davies-Meyer, HMAC, sponge, Merkle trees, random oracle model | The collision game itself is simple, but the birthday bound requires combinatorial probability arguments not yet available in Mathlib. |
| **Ch. 9** (Auth. encryption) | `SecretKey/AE.lean` | Empty scaffolding | AE definitions, encrypt-then-MAC, GCM, CCM | Depends on both CPA security (Ch. 5) and MAC security (Ch. 6). |

### Chapters with scaffolding only (10–17: public-key cryptography)

| Chapter | File | What is missing | Reason |
|---------|------|-----------------|--------|
| **Ch. 10** (Number-theoretic tools) | `PublicKey/Tools.lean` | Cyclic groups, discrete log, CDH, DDH assumptions, generic group model | Mathlib has `ZMod`, `IsCyclic`, and group theory, but connecting these to cryptographic hardness assumptions (as computational problems indexed by security parameter) requires careful design. |
| **Ch. 11–12** (Public-key encryption) | `PublicKey/Encryption.lean` | `PKEFamily` structure exists but no security games; ElGamal, Cramer-Shoup, hybrid encryption, RSA-OAEP all missing | Requires Ch. 10 algebraic infrastructure plus CPA/CCA security games with decryption oracles. |
| **Ch. 13–14** (Digital signatures) | `PublicKey/Signature.lean` | `SignatureFamily` structure exists but no security games; Schnorr, RSA-FDH, hash-and-sign, certificates all missing | Requires Ch. 10 group infrastructure and a multi-query signing oracle for existential unforgeability. |
| **Ch. 15** (Elliptic curves) | `PublicKey/EllipticCurve.lean` | EC group law, pairings, BLS signatures | Mathlib has `EllipticCurve` but connecting it to the cryptographic abstraction layer (as a source of cyclic groups for Ch. 10) is non-trivial. |
| **Ch. 16–17** (Lattices) | `PublicKey/Lattice.lean` | LWE, SIS, Ring-LWE, lattice-based encryption and signatures | Mathlib has basic lattice theory but lacks the specific worst-case/average-case reduction infrastructure needed for cryptographic lattice assumptions. |

### Chapters with scaffolding only (18–23: protocols)

| Chapter | File | What is missing | Reason |
|---------|------|-----------------|--------|
| **Ch. 18** (Identification) | `Protocols/Identification.lean` | ID schemes, Schnorr ID, Fiat-Shamir transform | Requires interactive protocol formalization (prover/verifier message exchange) and Ch. 10 group infrastructure. |
| **Ch. 19–20** (ZK proofs) | `Protocols/ZeroKnowledge.lean` | ZK definitions (completeness, soundness, zero-knowledge), Sigma protocols, NIZKs | Requires a simulation-based security framework and interactive protocol model. This is one of the most complex formalizations in the book. |
| **Ch. 21** (Key exchange) | `Protocols/KeyExchange.lean` | Diffie-Hellman, authenticated key exchange, TLS | Requires Ch. 10 group infrastructure, session-based security model with active adversaries. |
| **Ch. 22** (Threshold crypto) | `Protocols/Threshold.lean` | Secret sharing, threshold decryption/signatures, distributed key generation | Requires polynomial interpolation over finite fields (available in Mathlib) plus multi-party protocol model. |
| **Ch. 23** (MPC) | `Protocols/MPC.lean` | Secure computation, garbled circuits, oblivious transfer, GMW protocol | Requires a simulation-based security framework for multi-party protocols — the most infrastructure-heavy formalization in the book. |

### Summary of blocking dependencies

The missing content clusters around four infrastructure gaps:

1. **Multi-query oracle framework.** Chapters 5, 6, 9, 13–14 need adversaries that interact with oracles (encryption, signing, decryption) over multiple queries. Our current model supports only single-query adversaries.

2. **Hybrid/reduction argument support.** Chapters 3, 4, 8 need game-hopping proofs and birthday-bound arguments. The counting-based probability framework does not yet support reasoning about sequences of games.

3. **Algebraic infrastructure for cryptographic assumptions.** Chapters 10–15, 18, 21 need cyclic groups, discrete log, CDH/DDH as computational assumptions indexed by security parameter, connected to Mathlib's existing algebra.

4. **Simulation-based security.** Chapters 19–20, 22–23 need ideal/real world simulation paradigms for interactive and multi-party protocols.

## Building

```bash
lake build
```

Requires Lean 4 (v4.29.0-rc2) and Mathlib (fetched automatically by Lake).

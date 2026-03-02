# CSLib Protocols in Lean

![CSLib Protocols Project](./doc/cslib-protocols-logo.svg)

## Conservatively extending CSLib

We propose the addition of _Protocols_, and associated components, to CSLib. 
For example, _Cryptographic protocols_ could be added as follows,
```
CSLib
|
+ --- Systems
|      | 
|      + --- Distributed
|            |
|            + --- Protocols
|                  |
|                  + Cryptographic
+ --- Algorithms
|     | 
|     + --- Cryptography
.
.
.
```
with a new to level component for _Systems_ and a path from it to _Cryptographic Protocols_. The necessary math for them would be added to a new component _Cryptography_ under, say, _Algorithms_.

## Example

To illustrate our proposal we formalize three cryptographic protocols, one-time pad, $\sigma$-protocols and Schnorr's identification protocol, and place them into our proposed structure.

```
CSLib
|
+ --- Systems
|      | 
|      + --- Distributed
|            |
|            + --- Protocols
|                  |
|                  + Cryptographic
|                  |
|                  + --- One-time_pad
|                  |
|                  + --- Sigma_protocols
|                  |
|                  + --- Schnorr_Identification   
+ --- Algorithms
|     | 
|     + --- Cryptography
|           |
|           + --- Cyphertext
|           |
|           + --- ExpQ
.
.
.
```

### Cyphertext

A message, key, or ciphertext is represented as a vector of bits of length n. Operation XOR is lifted to vector of bits.

- Lean 4 source file: [Cyphertext.lean](../Cslib/Algorithms/Cryptography/Cyphertext.lean)

### Group of exponent q

These lemmas work over a commutative group $G$ whose every element has order dividing $q$,
where $q$ is prime. The key hypothesis throughout is:

  hG : ∀ x : G, xᑫ = 1

This is the defining property of a group of exponent $q$ — raising any element to the $q$-th
power gives the identity.

They are relevant in particular to Schnorr's Identification Protocol. We propose them to be in a particular file as they me of interest to other theories, and to illustrate our proposal. They of course can be moved
to Schnorr Identification module.

- Lean 4 source file: [ExpQ.lean](../Cslib/Algorithms/Cryptography/ExpQ.lean)

### One-Time Pad (OTP)

A One-Time Pad is a cipher where the key space, message space, and ciphertext space are all equal to {0,1}ⁿ for some n. Given a key k chosen uniformly at random from {0,1}ⁿ:

Encryption: E(k, m) = k ⊕ m
Decryption: D(k, c) = k ⊕ c
where ⊕ denotes bitwise XOR.

The one-time pad achieves perfect secrecy (Shannon secrecy): for every pair of messages m₀, m₁ and every ciphertext c, the probability that c was produced from m₀ equals the probability it was produced from m₁, when the key is uniformly random. Formally:

Pr[E(k, m₀) = c] = Pr[E(k, m₁) = c]

Key constraint: The key must be at least as long as the message and must never be reused — hence the name "one-time" pad. Reusing a key k for two messages m₁ and m₂ leaks m₁ ⊕ m₂, destroying security.

- Lean 4 source file: [OTP.lean](../Cslib/Systems/Distributed/Protocols/Cryptographic/OTP.lean).

### Sigma Protocols

A Sigma Protocol for R is a pair (P, V).

- P is an interactive protocol algorithm called the prover, which takes as input a witness-statement pair (x, y) ∈ R.
- V is an interactive protocol algorithm called the verifier, which takes as input a statement y ∈ Y, and which outputs accept or reject.
- P and V are structured so that an interaction between them always works as follows:

1. To start the protocol, P computes a message t, called the commitment, and sends t to V.
2. Upon receiving P's commitment t, V chooses a challenge c at random from a finite challenge space C, and sends c to P.
3. Upon receiving V's challenge c, P computes a response z, and sends z to V.
4. Upon receiving P's response z, V outputs either accept or reject, which must be computed strictly as a function of the statement y and the conversation (t, c, z). In particular, V does not make any random choices other than the selection of the challenge — all other computations are completely deterministic.

- Lean 4 source file: [Sigma.lean](../Cslib/Systems/Distributed/Protocols/Cryptographic/Sigma.lean).

### Schnorr's Identification Protocol (SIP)

Schnorr's Identification Protocol can be understood as an instance of a sigma protocol.

Let 𝔾 be a cyclic group of prime order q, and let g be a generator of 𝔾. The prover's secret key is α ←ᴿ ℤ_q, and the corresponding public key is u := gᵅ ∈ 𝔾.

The protocol proceeds as in a sigma protocol, as follows:

1. Commitment: The prover picks αₜ ←ᴿ ℤ_q, computes uₜ := gᵅᵗ, and sends uₜ to the verifier.
2. Challenge: The verifier picks c ←ᴿ ℤ_q and sends c to the prover.
3. Response: The prover computes α_z := αₜ + α · c (mod q) and sends α_z to the verifier.
4. Verification: The verifier accepts if and only if gᵅᶻ = uₜ · uᶜ.

- Lean 4 source file: [SchnorrId.lean](../Cslib/Systems/Distributed/Protocols/Cryptographic/SchnorrId.lean).

## Scripts

The script `scritps/url_gen.py` can be used to generate a URL-encoded string of a Lean file to directly open it on Live.
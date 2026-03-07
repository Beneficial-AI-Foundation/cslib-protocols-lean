/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.SecretKey.Encryption.SemanticSecurity
public import Cslib.Crypto.SecretKey.BlockCipher.PRF

@[expose] public section

/-!
# Chosen Plaintext Attack Security

This file formalizes CPA (chosen plaintext attack) security from Chapter 5 of Boneh-Shoup.

CPA security strengthens semantic security by allowing the adversary to request encryptions
of messages of its choice (modeling a scenario where the adversary can influence what gets
encrypted).

## Main definitions

- `CPAAdversary`: An adversary in the CPA security game, who can make encryption queries
  before and after receiving the challenge ciphertext. (Section 5.3)

- `CipherFamily.CPASecure`: A cipher family is CPA-secure if the CPA advantage is negligible
  for all efficient adversaries. (Definition in Section 5.3)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 5
-/

namespace Cslib.Crypto

-- TODO: Formalize CPA adversaries with multi-query oracle access
-- TODO: Formalize randomized counter mode (Section 5.4.2)
-- TODO: Formalize CBC mode (Section 5.4.3)
-- TODO: Formalize nonce-based encryption (Section 5.5)

end Cslib.Crypto

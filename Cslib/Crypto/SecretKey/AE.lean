/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.SecretKey.Encryption.SemanticSecurity
public import Cslib.Crypto.SecretKey.MAC.Basic

@[expose] public section

/-!
# Authenticated Encryption

This file formalizes authenticated encryption from Chapter 9 of Boneh-Shoup.

Authenticated encryption combines confidentiality (semantic security) with integrity
(ciphertext integrity), providing security against chosen ciphertext attacks.

## Main definitions

- `AEFamily`: A cipher family with an additional ciphertext integrity property.
  (Section 9.1)

- `AEFamily.CCASecure`: CCA security: semantic security even when the adversary has access
  to a decryption oracle. (Section 9.2.2)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 9
-/

namespace Cslib.Crypto

-- TODO: Formalize authenticated encryption definitions (Section 9.1)
-- TODO: Formalize CCA security (Section 9.2)
-- TODO: Formalize encrypt-then-MAC (Section 9.4.1)
-- TODO: Prove AE implies CCA security (Theorem 9.3)
-- TODO: Formalize nonce-based AEAD (Section 9.5)
-- TODO: Formalize GCM (Section 9.7)

end Cslib.Crypto

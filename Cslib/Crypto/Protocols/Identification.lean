/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Cslib.Crypto.PublicKey.Signature

@[expose] public section

/-!
# Identification and Sigma Protocols

This file formalizes identification protocols and Sigma protocols from Chapters 18–19
of Boneh-Shoup.

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023],
  Chapters 18–19
-/

namespace Cslib.Crypto

-- TODO: Formalize interactive protocol framework (Section 18.1)
-- TODO: Formalize ID protocol security (Section 18.2)
-- TODO: Formalize password protocols (Section 18.3)
-- TODO: Formalize Schnorr identification protocol (Section 19.1)
-- TODO: Formalize Sigma protocol framework (Section 19.4)
-- TODO: Formalize Fiat-Shamir heuristic (Section 19.6)
-- TODO: Formalize AND/OR proof composition (Section 19.7)

end Cslib.Crypto

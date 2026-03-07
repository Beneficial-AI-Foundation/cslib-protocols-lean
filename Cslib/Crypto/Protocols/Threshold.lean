/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Mathlib.RingTheory.Polynomial.Basic

@[expose] public section

/-!
# Threshold Cryptography

This file formalizes threshold cryptography from Chapter 22 of Boneh-Shoup.

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 22
-/

namespace Cslib.Crypto

-- TODO: Formalize Shamir secret sharing (Section 22.1) using Mathlib polynomials
-- TODO: Formalize threshold signatures (Section 22.2)
-- TODO: Formalize BLS threshold signing (Section 22.2.2)
-- TODO: Formalize threshold decryption (Section 22.3)
-- TODO: Formalize distributed key generation (Section 22.4)
-- TODO: Formalize monotone access structures (Section 22.5)

end Cslib.Crypto

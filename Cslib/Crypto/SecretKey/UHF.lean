/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Mathlib.Data.Fintype.Card

@[expose] public section

/-!
# Universal Hash Functions

This file formalizes universal hash functions (UHFs) from Chapter 7 of Boneh-Shoup.

## Main definitions

- `UHFamily`: A family of hash functions `H : Key → Msg → Tag` that is ε-universal:
  for distinct messages `m₀ ≠ m₁`, `Pr[H(k, m₀) = H(k, m₁)] ≤ ε` over random `k`.
  (Section 7.1)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 7
-/

namespace Cslib.Crypto

-- TODO: Formalize ε-universal hash families (Section 7.1)
-- TODO: Formalize polynomial-based UHFs (Section 7.2.1)
-- TODO: Formalize PRF(UHF) composition (Section 7.3)
-- TODO: Formalize Carter-Wegman MAC (Section 7.4)

end Cslib.Crypto

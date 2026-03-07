/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Mathlib.Data.Fintype.Card
public import Mathlib.GroupTheory.SpecificGroups.Cyclic

@[expose] public section

/-!
# Public Key Tools

This file formalizes the core public key primitives from Chapter 10 of Boneh-Shoup:
one-way trapdoor functions, the RSA assumption, and Diffie-Hellman key exchange.

## Main definitions

- `TrapdoorPermFamily`: A trapdoor permutation scheme. (Section 10.2)
- `DLAssumption`: The discrete logarithm assumption in a cyclic group. (Section 10.5)
- `CDHAssumption`: The computational Diffie-Hellman assumption. (Section 10.5)
- `DDHAssumption`: The decisional Diffie-Hellman assumption. (Section 10.5)

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 10
-/

namespace Cslib.Crypto

-- TODO: Formalize one-way trapdoor function schemes (Section 10.2)
-- TODO: Formalize RSA trapdoor permutation (Section 10.3)
-- TODO: Formalize Diffie-Hellman key exchange protocol (Section 10.4)
-- TODO: Formalize DL, CDH, DDH assumptions (Section 10.5)

end Cslib.Crypto

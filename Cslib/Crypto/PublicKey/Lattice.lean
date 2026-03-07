/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Mathlib.Analysis.InnerProductSpace.Basic

@[expose] public section

/-!
# Post-Quantum Cryptography from Lattices

This file formalizes lattice-based cryptography from Chapter 17 of Boneh-Shoup.

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 17
-/

namespace Cslib.Crypto

-- TODO: Formalize integer lattices (Section 17.1)
-- TODO: Formalize SIS problem (Section 17.2.1)
-- TODO: Formalize LWE problem (Section 17.2.2)
-- TODO: Formalize Ring-LWE (Section 17.2.3)
-- TODO: Formalize lattice-based signatures (Section 17.4)
-- TODO: Formalize lattice-based PKE (Section 17.5)
-- TODO: Formalize FHE (Section 17.6)

end Cslib.Crypto

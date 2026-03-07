/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Cslib.Crypto.Protocols.Identification

@[expose] public section

/-!
# Proving Properties in Zero-Knowledge

This file formalizes zero-knowledge proof systems from Chapter 20 of Boneh-Shoup.

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 20
-/

namespace Cslib.Crypto

-- TODO: Formalize NP languages and soundness (Section 20.1)
-- TODO: Formalize non-interactive proof systems (Section 20.3)
-- TODO: Formalize NIZK (Section 20.3.5)
-- TODO: Formalize Bulletproofs (Section 20.5)
-- TODO: Formalize SNARKs (Section 20.6)

end Cslib.Crypto

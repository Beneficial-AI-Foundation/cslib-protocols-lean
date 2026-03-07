/-
Copyright (c) 2025 Beneficial AI Foundation. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
Authors: Beneficial AI Foundation
-/

module

public import Cslib.Crypto.Init
public import Cslib.Crypto.PublicKey.Tools

@[expose] public section

/-!
# Authenticated Key Exchange

This file formalizes authenticated key exchange protocols from Chapter 21 of Boneh-Shoup.

## References

* [D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*][BonehShoup2023], Chapter 21
-/

namespace Cslib.Crypto

-- TODO: Formalize AKE security model (Section 21.9)
-- TODO: Formalize perfect forward secrecy (Section 21.3)
-- TODO: Formalize PAKE protocols (Section 21.11)
-- TODO: Formalize TLS 1.3 handshake model (Section 21.10)

end Cslib.Crypto

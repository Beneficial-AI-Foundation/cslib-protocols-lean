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
.
.
.
```
with a new to level component for _Systems_ and a path from it to _Cryptographic Protocols_. 

## Example

To illustrate our proposal we formalize three cryptographic protocols, one-time pad, 
$\sigma$-protocols, Schnorr's identification protocol, key exchange protocols and Diffie-Hellmann 
protocols, placing them into our proposed structure. 

One-time pad is specified in file 
[`Basic.lean`](../Cslib/Systems/Distributed/Protocols/Cryptographic/Basic.lean) under folder 
`Cryptographic`. Sigma protocols in general are specified in file 
[`Sigma/Basic.lean`](../Cslib/Systems/Distributed/Protocols/Cryptographic/Sigma/Basic.lean), as a 
_type class_ in Lean. Schnorr's Identification protocol is specified in file 
[`Sigma/SchnorrId.lean`](../Cslib/Systems/Distributed/Protocols/Cryptographic/Sigma/SchnorrId.lean) as 
an instance of the type class `SigmaProtocols` in 
[`Sigma/Basic.lean`](../Cslib/Systems/Distributed/Protocols/Cryptographic/Sigma/Basic.lean).
The type class `KeyExchange` in 
[`KeyExchange/Basic.lean`](../Cslib/Systems/Distributed/Protocols/Cryptographic/KeyExchange/Basic.lean) 
is instantiated in 
[`KeyExchange/Diffie-Hellman.lean`](../Cslib/Systems/Distributed/Protocols/Cryptographic/KeyExchange/Diffie-Hellman.lean) 
where the structure of the three-phase protocol and its algebraic properties are specified and proven.
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
|                  + --- Basic.lean
|                  |
|                  + --- Sigma
|                  |     |
|                  |     + --- Basic.lean .......
|                  |     |                      .
|                  |     |                      . import
|                  |     + --- SchnorrId.lean <..
|                  |
|                  + --- KeyExchange
|                        |
|                        + --- Basic.lean ............
|                        |                           . import
|                        + --- Diffie-Hellman.lean <.. 
.
.
.
```
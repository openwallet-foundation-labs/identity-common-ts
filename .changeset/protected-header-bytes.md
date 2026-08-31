---
'@owf/cose': patch
---

Keep the protected header bytes a COSE structure was decoded from, so a token verifies against what its issuer actually signed.

RFC 9052 puts the protected headers into the `Sig_structure` / `MAC_structure` as an opaque bstr, so what is signed is the exact bytes the issuer sent. `ProtectedHeaders` only kept the decoded header map and re-encoded it on every use, which is not byte-preserving for input that is valid CBOR but not the form we would write — a non-shortest-form integer, an indefinite-length map, a float, a bignum, a tag 0 date. The signature over such a token then failed to verify, reported as an invalid signature with nothing to point at the real cause.

`ProtectedHeaders` now retains the bstr it was decoded from and returns it from `encodedStructure`, the same way `Cwt` already retained the payload bytes. `Sign1`, `Mac0` and `Cwt` pick this up without changes, including through the re-decode into a CWT type's own header class.

The retained bytes are dropped as soon as the header map is changed, so headers that are modified before signing encode from the map as before. A change the map cannot see — a header *value* mutated in place, e.g. `headers.get(x5chain)[0] = ...` — has to be reported with the new `ProtectedHeaders.markModified()`, which is the `Cwt.markPayloadModified()` of the header side.

`CwtStructureClass` (the structural type `Cwt.fromToken` takes its structures as) now describes `fromEncodedStructure` as returning the structure instance rather than something to re-wrap, since re-wrapping an instance around its decoded structure drops state like these bytes. Every `CborStructure` subclass already satisfies it.

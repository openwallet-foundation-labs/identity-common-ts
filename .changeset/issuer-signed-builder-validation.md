---
'@owf/mdoc': minor
---

`Issuer` and `IssuerSignedBuilder` refuse to create a credential that does not conform to ISO/IEC 18013-5:

- Signing throws an `InvalidValidityInfoError` when `validFrom` is before `signed`, or when `validUntil` is not later than `validFrom` (9.1.2.4).
- Adding an element identifier that is already in the namespace throws a `DuplicateElementIdentifierError` (8.3.2.1.2.2). Before, both elements were added.
- Adding an element throws when its random digest ID is already used in the namespace. Before, the digest of the first element was silently replaced in the MSO.

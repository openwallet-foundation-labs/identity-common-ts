---
'@owf/eudi-lote': minor
---

Align `validateLoTE` with the ETSI TS 119 602 v1.1.1 JSON schema. The schema is vendored unchanged with its licence, and a test runs it with ajv over the same documents as `validateLoTE`; the few places where the two still differ are listed in that test with their reason (see below). Rules that only the EU lists impose moved from the base schema to the profiles, so `validateLoTEProfile` still applies them.

Now accepted by `validateLoTE`:

- a list without `TrustedEntitiesList`, as the EC lists publish a list with no entities;
- `LoTELegalNotice` as a plain string, as in the JSON schema, as well as a localized string;
- a service supply point without `ServiceType`, and a postal address without `Locality` or `PostalCode`;
- RFC 3339 date-times with a UTC offset, a lowercase `t` or `z`, or a leap second, not only `Z`;
- empty strings where the JSON schema allows them: `lang`, `value`, a certificate's `val`, `MimeType`;
- a `Country` that is not a 2-letter code, and a `ServiceDigitalIdentity` with no identity;
- any URI as a certificate's `encoding` and any string as its `specRef`, and `oct` as a JWK `kty`.

Now rejected by `validateLoTE`, as the JSON schema does: a `PolicyOrLegalNotice` that is empty, that has an item with neither key, that mixes policies and legal notices, or whose items all carry both `LoTEPolicy` and `LoTELegalNotice` (the schema's `oneOf`: every item has `LoTEPolicy`, or every item has `LoTELegalNotice`, not both). The exported `PkiObjectSchema` also requires its `encoding` to be a URI, as the schema's `pkiOb` does.

Still checked by the EU profiles in `validateLoTEProfile`, on the scheme information, the pointers to other lists, the entities and the service history: non-empty `lang` and `value`, a 2-letter `Country`, at least one digital identity, a non-empty certificate `val`, `encoding` `urn:ietf:params:tls-cert-type:x509` and `specRef` `RFC5280` when present, no `oct` key, a non-empty `MimeType`.

Known differences from the JSON schema, kept on purpose: `validateLoTE` still accepts an empty `TrustedEntitiesList`, an entity without `TEInformationURI`, a localized `LoTELegalNotice`, empty optional arrays, an `OKP` key, a non-integer `HistoricalInformationPeriod`, a `ServiceType` that is not a URI and unknown properties. It rejects a few values the schema's formats let through: a URI that the WHATWG URL parser refuses (a port above 65535, for example), a date-time with a space instead of `T` or an offset without a colon, and integers above 2^53 - 1.

Fixed: the EUEAAProvidersList and EUPubEAAProvidersList profiles rejected every list, because their expected `StatusDeterminationApproach` ended in a stray `"`.

Other changes:

- `createLoTE` leaves `TrustedEntitiesList` out when there are no entities, instead of writing `[]`, which the JSON schema rejects (`minItems: 1`), and writes no key for an optional field left undefined.
- `removeTrustedEntity` removes the key when the last entity goes. When no entity matches, it returns the list as it was: it no longer adds the key to a list that had none.
- `ServiceBuilder.addEndpoint(uri)` adds a supply point without `ServiceType`; `addEndpoint(type, uri)` is unchanged.
- New exports: `PolicyOrLegalNoticeListSchema` and `hasDigitalIdentity`.

Breaking type and behaviour changes:

- `LoTE.TrustedEntitiesList` may be `undefined`: check it before iterating, including on lists made by `createLoTE` without entities.
- `PolicyOrLegalNotice[].LoTELegalNotice` may be a `string` or a `{ lang, value }` object: reading `.value` alone gets `undefined` on a string.
- `X509CertificateRef.encoding` and `.specRef` are typed `string`, no longer the literals `urn:ietf:params:tls-cert-type:x509` and `RFC5280`.
- `JWKPublicKey.kty` adds `oct`.
- `validateLoTE`, `assertValidLoTE` and the `trustedEntity()` and `service()` builders check the JSON schema rules only. A list or entity that failed them before may now pass with a 3-letter country, an empty name or no service identity: run `validateLoTEProfile` for the EU rules.
- `validateLoTE` rejects the `PolicyOrLegalNotice` forms listed above, which it used to accept, and `PkiObjectSchema` rejects an `encoding` that is not a URI.

---
"@owf/eudi-wrprc": minor
---

Bring the WRPRC implementation in line with the letter of ETSI TS 119 475 v1.2.1, so it interoperates with other SDKs that implement the specification as written.

- Produce and check a real JAdES B-B signature, as GEN-5.2.1-04 requires. `signWRPRC` now builds the token through `@owf/eudi-jades`, so the protected header carries the `iat` claimed signing time of ETSI TS 119 182-1 alongside `typ`, `alg` and `x5c`, and a `signingTime` option pins it. `decodeWRPRC` rejects tokens that fail the B-B profile. Table 5 is a minimum set rather than an exhaustive one, so the header keeps requiring `iat`.
- Accept the full JAdES B-B algorithm set of ETSI TS 119 182-1 clause 5.1.2 (`PS256`/`PS384`/`PS512` and `EdDSA` in addition to `ES*` and `RS*`), exported as `WRPRC_JWS_ALGORITHMS`.
- Restrict emitted `provides_attestations` to `Credential` objects, as required by Table 8 and Annex B.2.1, while continuing to accept an array of scheme URLs on input for the form anticipated in a later edition.
- Accept the anticipated `claims` and `intermediary.name` spellings when parsing, normalizing both to the published `claim` and `intermediary.sname`. Writing stays on the published edition unless the new `dialect` option selects `WRPRC_DIALECTS.DRAFT`, which is unstable and not the default. `normalizeWRPRCPayload`, `toWRPRCDialect` and `parseWRPRCPayload` expose the mapping.
- Allow DCQL claims path pointers to contain integers and `null` in addition to strings, matching the pointer semantics the specification defers to.
- Correct the identifier type to prefix mapping, which differs between legal persons (Table 2, where the TIN type maps to `VAT`) and natural persons (Table 4). `IDENTIFIER_TYPE_TO_PREFIX` is replaced by `LEGAL_PERSON_IDENTIFIER_PREFIXES` and `NATURAL_PERSON_IDENTIFIER_PREFIXES`, and `getIdentifierPrefix` takes a subject type. `TAX` is no longer accepted as a natural person prefix, and `TIN` no longer as a legal person one.
- Warn through the new `unknown_identifier_prefix` code when `sub` uses initial characters outside Tables 2 and 4. The prefix lists previously fed an empty `if` block, so they had no effect at all.
- Fix `WRPRCBuilder.serviceDescription`, which grouped by language. `srv_description` is an array of services each localized into several languages (B.2.1, Annex C), so localizing one service into two languages produced two services instead of one. Consecutive calls now localize the same service, and repeating a language starts the next one.
- Warn when a Service_Provider WRPRC omits `credentials` or `purpose` (GEN-5.2.4-06) via the new `missing_credentials` and `missing_purpose` validation codes.

The README now documents which editorial defects of the specification the library reproduces on purpose, notably the singular `claim` subfield inside `Credential` and `intermediary.sname` from the normative Table 10 rather than `name` from the informative Annex C example.

Breaking: `addProvidedAttestation` rejects mixing credential objects and scheme URLs in one payload.

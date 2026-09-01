# @owf/eudi-wrprc

## 0.4.0

### Minor Changes

- b7e7f15: Add `dateToSeconds`, `secondsToDate` and `nowInSeconds` to `@owf/identity-common`, and use them in `@owf/eudi-wrprc` in place of inline `* 1000` and `/ 1000` arithmetic.
  
  Type the codes that `validateWRPRCPayload` emits. `WRPRC_VALIDATION_CODES` and the `WRPRCValidationCode` union are exported, so a calling application can branch on a specific failure instead of matching message text. The `code` field stays open to strings because schema issues forward zod's own codes. `ValidationError` and `ValidationResult` are now exported as well.
- 947007b: Add an optional `jti` claim to the WRPRC payload, so a certificate can be referenced by an identifier.
  
  - `WRPRCPayloadSchema` accepts an optional non-empty `jti` (RFC 7519). ETSI TS 119 475 does not define the claim, so it is never generated: a payload built without one carries no identifier, and payloads issued elsewhere without one stay valid.
  - New builder method `certificateId(id)` sets `jti`, for issuers that have their own identifier scheme. Pass `crypto.randomUUID()` for a random one.
- caf884c: Bring the WRPRC implementation in line with the letter of ETSI TS 119 475 v1.2.1, so it interoperates with other SDKs that implement the specification as written.
  
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
- b7e7f15: Align the WRPRC payload with ETSI TS 119 475 v1.2.1.
  
  - Add the Table 10 optional attributes `public_body`, `exp` and `intermediary.sname`, the latter replacing `intermediary.name`. Add the `act` claim required by GEN-5.2.4-09, and `intended_use_id` from Table 9.
  - Add `iat` to `WRPRCPayloadSchema`. Table 7 lists it as a payload field, and the builder set it already, but `build()` parsed it away, so every payload it returned lost its issuance time.
  - Accept entitlements in the Annex A.2 OID form as well as the URI form (GEN-5.2.4-03). Values outside Annex A still raise a warning.
  - Validate that `exp` falls at most 12 months after `iat` (GEN-5.2.4-08), and that `act.sub` matches the intermediary identifier under intermediation (GEN-5.2.4-09).
  
  Breaking: payloads carrying `intermediary.name`, and payloads without `iat`, no longer validate.

### Patch Changes

- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
- Updated dependencies [a986752]
- Updated dependencies [c55b5d0]
  - @owf/identity-common@0.4.0
  - @owf/eudi-jades@0.4.0
  - @owf/crypto@0.4.0

## 0.3.2

### Patch Changes

- d0c90bd: add json schema generator
- be9f7cf: Rename content to value field to align with spec
- 06f362e: move iat to header for jwt and cwt
- 9806aba: provides attestation is a list of strings
  - @owf/crypto@0.3.2
  - @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- @owf/crypto@0.3.1
- @owf/identity-common@0.3.1

## 0.3.0

### Patch Changes

- Updated dependencies [353df0c]
  - @owf/identity-common@0.3.0
  - @owf/crypto@0.3.0

## 0.2.0

### Patch Changes

- b79d4ba: align package json for export
- 293e5ec: Also include commonjs builds
- 0bc3d9a: fix purpose field from value to content
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
- Updated dependencies [6bd9c63]
  - @owf/identity-common@0.2.0
  - @owf/crypto@0.2.0

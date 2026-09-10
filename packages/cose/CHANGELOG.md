# @owf/cose

## 0.4.0

### Minor Changes

- 46a42a3: Verify a CWT from the CWT itself.
  
  `CwtPayload.verifyClaims` checks the claims set: that the claims the CWT type requires are present, that `iss` / `sub` / `aud` are the expected ones, and that the token is within its validity window (compared against `now` with a `skewSeconds` of 30 seconds by default). Nothing is required unless `requiredClaims` says so (or an extended `CwtPayload` class defines it as required).
  
  A CWT type overrides/extends `verifyClaims` to apply its own rules, and the options it takes travel with it: `Cwt.verifyClaims` and `Cwt.verify` forward the payload class's own option type, so a CWT type that requires more than the registered claims requires it on the `Cwt` methods too.
  
  `Cwt.verify` verifies a token completely (signature/tag and claims + subclass verifications):
  
  ```ts
  await cwt.verify({ key, expectedSubject: 'https://example.com/statuslists/1' }, { sign1: sign1Context })
  ```
  
  The verify method supports both `Sign1` and `Mac0` verification, so the `ctx` takes a callback for each (both optional) To make that distinction available, `Cwt` now holds `signature` and `tag` separately instead of one merged `signatureOrTag` field. `signatureOrTag` remains as a read-only getter over the two, and a CWT constructed with both is rejected.
- 46a42a3: Supply `externalAad` at the call that uses it, rather than holding it on the structure. It is now a parameter of every sign and verify call that may use it. This fixes an issue where the property was not correctly used when provided.
  
  ```ts
  const token = await cwt.signAndEncode({ signingKey, algorithm, externalAad }, sign1Context)
  await Cwt.fromToken(token, { payload: CwtPayload }).verify({ key, externalAad }, { sign1: sign1Context })
  ```
  
  Breaking: `externalAad` is removed from `Sign1Options`, `Mac0Options` and `CwtOptions`, and from the `Sign1.externalAad` / `Mac0.externalAad` / `Cwt.externalAad` properties. Pass it to the call instead.
- 46a42a3: Typed CWT payload and headers, extensible per CWT type.
  
  A CWT type is expressed by the structures it is made of, each validating itself through its own `encodingSchema`. `Cwt` holds no schemas and no per-type statics.
  
  - Payload: a `CwtPayload` subclass, schema from `extendCwtPayloadClaims`. The registered RFC 8392 claims are typed accessors (`issuer`, `subject`, `audience`, `expirationTime`, `notBefore`, `issuedAt`, `cwtId`); `getClaim` reads any claim, `unknown` if undeclared. A claim redeclared as required is no longer optional on the inherited accessor.
  - Headers: a `ProtectedHeaders` / `UnprotectedHeaders` subclass, schema from `extendCoseHeaderClaims` (wrapped in `protectedHeadersSchema` for the protected bucket, which is carried in a bstr). Each bucket validates only against its own schema, so a parameter that must be integrity protected cannot be satisfied by an unprotected copy.
  - Decoding names the classes, and types the result from them:
  
  ```ts
  const cwt = Cwt.fromToken(token, {
    payload: StatusListCwtPayload,
    protectedHeaders: StatusListCwtProtectedHeaders,
  })
  ```
  
  A CWT type that carries extra logic subclasses `Cwt` and overrides `fromToken` to supply them, so callers do not repeat the classes.
  
  `typ` (16, RFC 9596) is now `RegisteredCwtHeaderClaimKey.Typ`, readable as `Cwt.typ`. `typ` and `algorithm` read the protected headers only; `keyId` falls back to unprotected.
  
  Breaking changes:
  
  - `CwtOptions` is no longer `Sign1Options | Mac0Options`. `Cwt` takes a `CwtPayload` as `payload` plus `signatureOrTag`; the signed bytes are `payloadBytes`.
  - `Cwt.payload` is a `CwtPayload`, not `Uint8Array | null`. A detached payload throws `CwtDetachedPayloadError` at `fromToken`, an invalid claims set `CwtPayloadDecodeError`.
  - `Cwt.fromToken` requires the structures as a second argument, e.g. `Cwt.fromToken(token, { payload: CwtPayload })`.
  - `ProtectedHeaders` / `UnprotectedHeaders` are typed by their header map, so `decodedStructure` reflects the profile's map.
  - `StatusListCwtPayload.getCustomClaim` is replaced by `getClaim`, which infers the value type instead of taking it as a type argument.
  - `StatusListCwtHeaderKey` is removed; use `RegisteredCwtHeaderClaimKey.Typ`.
  - `StatusListCwt` requires protected `typ` = `application/statuslist+cwt`, via the new `StatusListCwtProtectedHeaders`. Still defaulted when absent, but a token with a different `typ` is now rejected.

### Patch Changes

- 46a42a3: Keep the protected header bytes a COSE structure was decoded from, so a token verifies against what its issuer actually signed.
  
  RFC 9052 puts the protected headers into the `Sig_structure` / `MAC_structure` as an opaque bstr, so what is signed is the exact bytes the issuer sent. `ProtectedHeaders` only kept the decoded header map and re-encoded it on every use, which is not byte-preserving for input that is valid CBOR but not the form we would write — a non-shortest-form integer, an indefinite-length map, a float, a bignum, a tag 0 date. The signature over such a token then failed to verify, reported as an invalid signature with nothing to point at the real cause.
  
  `ProtectedHeaders` now retains the bstr it was decoded from and returns it from `encodedStructure`, the same way `Cwt` already retained the payload bytes. `Sign1`, `Mac0` and `Cwt` pick this up without changes, including through the re-decode into a CWT type's own header class.
  
  The retained bytes are dropped as soon as the header map is changed, so headers that are modified before signing encode from the map as before. A change the map cannot see — a header *value* mutated in place, e.g. `headers.get(x5chain)[0] = ...` — has to be reported with the new `ProtectedHeaders.markModified()`, which is the `Cwt.markPayloadModified()` of the header side.
  
  `CwtStructureClass` (the structural type `Cwt.fromToken` takes its structures as) now describes `fromEncodedStructure` as returning the structure instance rather than something to re-wrap, since re-wrapping an instance around its decoded structure drops state like these bytes. Every `CborStructure` subclass already satisfies it.
- 8c4c570: Add a `keyLabels` option to `typedMap`, so validation errors can name a numeric CBOR label instead of only showing the number: `Expected key 'ExpirationTime (4)' to be defined.` A numeric TypeScript enum can be passed directly, and several can be merged with a spread.
- Updated dependencies [b7e7f15]
- Updated dependencies [5934a14]
  - @owf/identity-common@0.4.0

## 0.3.2

### Patch Changes

- @owf/identity-common@0.3.2

## 0.3.1

### Patch Changes

- @owf/identity-common@0.3.1

## 0.3.0

### Minor Changes

- 4bd7eb7: fix: correctly handle detached payload vs payload on sign1 and mac0. The detached payload is not available on the Sign1 and Mac0 classes anymore, and should be provided to the method classes directly. Detached payload cannot be provided anymore when embedded payload is already present. The `mac0` and `sign1` structures are not passed anymore to the context, but the already encoded data is provided.
- dad635c: refactor: only allow CoseKey as return value for getPublicKey in x509 context
- 6309c48: Reworked the handling of algorithm name extraction:

  - `alg` is only extracted from protected headers for Mac0 and Sign1
  - No error is thrown when the alg cannot be extracted, since it's not a required parameter according to the COSE spec
  - `algorithmName` on the Mac0 and Sign1 classes have been replaced by `algorithm` (COSE Algorithm identifier, number) and `jwaAlgorithm` (JOSE Algorithm identifier, string)
  - `algorithm` is now provided to the verification methods in Sign1 and Mac0 context as optional parameter
  - The `alg` parameter in `x509.getPublicKey` context method has been renamed to `algorithm` is now a COSE algorithm identifier, and optional due to `alg` not being required in Mac0 and Sign1 anymore.

- dad635c: refactor: only allow CosKey for sign1.verify
- 353df0c: fix: do now allow array of certificates in x509 context
- 353df0c: refactor: rename Mac0Context 'mac' method to 'authenticate'
- 2b0eeaf: Type the known COSE header claims. `kid` (label 4) is now validated as a bstr when decoding protected and unprotected headers, so a malformed `{ 4: undefined }` is rejected for every `Sign1`-derived structure (e.g. a `deviceSignature`) instead of being silently accepted. The other registered labels are enumerated as known keys; additional/private-use labels still pass through. `ProtectedHeaders`/`UnprotectedHeaders` now back their structure with a `TypedMap`, and the `.headers` accessor keeps `kid` typed as a bstr while allowing access to any other integer label.

### Patch Changes

- f1f42db: - cosekey algorithm now also can be MacAlgorithm
  - Some support for ed25519 to get the public and private key
- 353df0c: feat: add status list info objects for referenced status list token
- Updated dependencies [353df0c]
  - @owf/identity-common@0.3.0

## 0.2.0

### Patch Changes

- b79d4ba: align package json for export
- Updated dependencies [b79d4ba]
- Updated dependencies [7ef6497]
- Updated dependencies [f50ec6e]
- Updated dependencies [293e5ec]
  - @owf/identity-common@0.2.0

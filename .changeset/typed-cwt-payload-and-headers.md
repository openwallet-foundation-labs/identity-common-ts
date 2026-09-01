---
'@owf/cose': minor
'@owf/token-status-list': minor
---

Typed CWT payload and headers, extensible per CWT type.

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

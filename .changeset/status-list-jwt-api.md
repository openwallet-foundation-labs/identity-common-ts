---
'@owf/token-status-list': minor
---

BREAKING: the Status List Token JWT API is built on `@owf/jose`:

| Removed | Use instead |
| --- | --- |
| `getListFromStatusListJwt(jwt)` | `decodeStatusListJwt(jwt).statusList` |
| `getStatusListFromJwt(jwt)` | `decodeJwt({ jwt, payloadSchema: zJwtWithStatusListPayload }).payload.status.status_list` of `@owf/jose` |
| `verifyStatus({ token, idx, uri })` | `verifyStatusListJwt({ jwt, idx, uri, verifyJwsCallback })`, which also verifies the signature |
| `verifyStatusListJwtHeader(header)` | `decodeStatusListJwt(jwt)`, which rejects a token with a missing or wrong `typ` or `alg` |

`signStatusListJwt` creates and signs a Status List Token, and the `zStatusListJwtHeader`, `zStatusListJwtPayload`, `zJwtWithStatusListPayload` and `zStatusListEntry` schemas are exported. A token without `sub`, `iat` or a valid `status_list` is rejected when it is decoded.

BREAKING: `createHeaderAndPayload` validates its input instead of mutating it, sets `typ` to `statuslist+jwt` only when it is missing and rejects any other `typ`, and includes the `aggregation_uri` of the list. `verifyStatusListJwtClaims` takes the claim verification options of `@owf/jose`: `requiredClaims: ['exp']` replaces `requireExpirationTime`, and `checkIssuedAt` replaces `checkFreshness`.

BREAKING: creating, decoding, signing and verifying a token raise the `@owf/jose` errors, which this package re-exports, instead of an `IdentityCommonError` or `StatusListError`: a `JoseParseError` (or `JoseValidationError`) for a token that is not a Status List Token, and a `JoseVerificationError` for one that does not verify. A status list that cannot be decompressed still raises a `StatusListError`, and a status at `idx` that is not valid a `StatusListEntryNotValidError`.

---
'@owf/token-status-list': minor
---

BREAKING: the Status List Token JWT API is built on `@owf/jose`:

| Removed | Use instead |
| --- | --- |
| `createHeaderAndPayload(list, payload, header)` | `signStatusListJwt({ statusList, payload, header, signer, signJwsCallback })` |
| `getListFromStatusListJwt(jwt)` | `decodeStatusListJwt(jwt).statusList` |
| `getStatusListFromJwt(jwt)` | `decodeJwt({ jwt, payloadSchema: zReferencedTokenJwtPayload }).payload.status.status_list` of `@owf/jose` |
| `verifyStatus({ token, idx, uri })` | `verifyStatusListJwt({ jwt, idx, uri, verifyJwsCallback })`, which also verifies the signature |
| `verifyStatusListJwtHeader(header)` | `decodeStatusListJwt(jwt)` |
| `StatusListEntry`, `JwtWithStatusListPayload` | `StatusListReference`, `ReferencedTokenJwtPayload` |

The new `zStatusListJwtHeader`, `zStatusListJwtPayload`, `zReferencedTokenJwtPayload`, `zStatusClaim` and `zStatusListReference` schemas validate tokens as Token Status List draft 16 requires. `signStatusListJwt` only signs a `typ` of `statuslist+jwt`.

BREAKING: `verifyStatusListJwtClaims` takes the options of `verifyJwtClaims` of `@owf/jose`: `requiredClaims: ['exp']` replaces `requireExpirationTime`, and `checkIssuedAt` replaces `checkFreshness`. Errors are the `@owf/jose` errors, re-exported here. Claims that don't verify throw a `JoseValidationError` with an issue per claim.

`StatusList.getStatus` and `setStatus` throw a `StatusListError` for an index outside the list, a fraction or `NaN`, instead of a plain `Error`. A `ttl` that is not a positive number is rejected (draft 16 § 5.1 and § 5.2).

BREAKING: `StatusListEntryNotValidError` is replaced by `StatusListValidationError`, with an issue code of `STATUS_LIST_VALIDATION_CODES`. Verifying the status at an `idx`, with `verifyStatusListJwt` or `verifyStatus` of a status list CWT, throws it with `status_not_valid` (`{ idx, status }`) for a status that is not Valid and `index_out_of_range` (`{ idx, totalStatuses }`) for an `idx` outside the list. `StatusList.decompressStatusListFromBytes` throws it with `invalid_status_list` for bytes that are not a compressed status list, instead of a plain `Error`.

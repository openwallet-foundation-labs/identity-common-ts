---
'@owf/token-status-list': minor
---

Add `validateStatusListJwt(header, payload, options)`, which checks a Status List Token in JWT format against draft-ietf-oauth-status-list-16 and reports every problem as a finding instead of throwing at the first one: `typ`, `alg`, `sub` (against `uri` when given), `iat`, `nbf`, `exp`, `ttl`, and `bits`, `lst` and `aggregation_uri` of `status_list`. The missing RECOMMENDED `exp` and `ttl` are warnings. The findings are `Finding`s of `@owf/identity-common`, with codes from `STATUS_LIST_VALIDATION_CODES` and the section of the draft as `requirement`, and the result carries the decoded `StatusList`. The signature is not verified.

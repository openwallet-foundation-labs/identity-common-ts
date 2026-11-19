---
'@owf/token-status-list': patch
---

`decodeStatusListJwt` and `verifyStatusListJwt` take a `headerSchema` and a `payloadSchema`, applied on top of `zStatusListJwtHeader` and `zStatusListJwtPayload`. They type the `header` and `payload` these functions return.

---
"@owf/eudi-wrprc": minor
---

Add an optional `jti` claim to the WRPRC payload, so a certificate can be referenced by an identifier.

- `WRPRCPayloadSchema` accepts an optional non-empty `jti` (RFC 7519). ETSI TS 119 475 does not define the claim, so it is never generated: a payload built without one carries no identifier, and payloads issued elsewhere without one stay valid.
- New builder method `certificateId(id)` sets `jti`, for issuers that have their own identifier scheme. Pass `crypto.randomUUID()` for a random one.

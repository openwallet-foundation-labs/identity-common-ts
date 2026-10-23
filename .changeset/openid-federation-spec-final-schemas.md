---
'@owf/openid-federation': minor
---

Read and write entity statements of OpenID Federation 1.0 final only; support for earlier drafts is removed.

- Trust marks use `trust_mark_type` (Sections 3.1.2 and 7.1). The draft `id` is no longer read: a trust mark without `trust_mark_type` is rejected. The `trust_mark_type` of a `trust_marks` entry must be the one of its trust mark JWT.
- `iat`, `exp` and the other date claims must be NumericDate values (seconds since the epoch, RFC 7519) when statements are parsed and created. ISO strings and `Date` objects are rejected; parsed claims still return `Date` objects (openwallet-foundation-labs/openid-federation-ts#23).
- Decoded JWTs, such as `trust_marks[].trust_mark`, keep the compact JWT in `jwt`, so a trust mark can be verified.
- Metadata keeps parameters and entity types the schemas do not define. Before, for example, `token_endpoint` of `oauth_authorization_server` and every unknown entity type were dropped, also from `resolvedLeafMetadata`.
- `client_registration_types` and `client_registration_types_supported` are optional for all entity types (RECOMMENDED in Sections 5.1.2 and 5.1.3) and accept values other than `automatic` and `explicit`.

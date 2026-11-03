---
'@owf/identity-common': minor
'@owf/crypto': minor
'@owf/x509': minor
'@owf/token-status-list': minor
'@owf/cose': minor
'@owf/openid-federation': minor
'@owf/mdoc': minor
'@owf/eudi-jades': minor
'@owf/eudi-attestation-schema': minor
'@owf/eudi-sca': minor
'@sd-jwt/core': minor
'@sd-jwt/sd-jwt-vc': minor
---

Error classes are named `FooError` and zod schemas `zFoo` in all packages.

**Breaking:** `*Exception` is renamed to `*Error`, e.g. `IdentityException` to `IdentityError`, `SDJWTException` to `SdJwtError`, `JwtTimeClaimException` to `JwtTimeClaimError`, `X509Exception` to `X509Error` and `SLException` to `StatusListError`. The `name` of the errors changes with it. Zod schemas are renamed from `FooSchema` (or `fooSchema`) to `zFoo`, e.g. `TypeMetadataFormatSchema` to `zTypeMetadataFormat`, `SchemaMetaSchema` to `zSchemaMeta`, `issuerSignedItemSchema` to `zIssuerSignedItem` and `Iso4217CurrencyCode` to `zIso4217CurrencyCode`.

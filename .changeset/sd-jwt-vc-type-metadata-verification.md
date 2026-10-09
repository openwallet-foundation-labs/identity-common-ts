---
"@sd-jwt/sd-jwt-vc": minor
---

Add `verifyTypeMetadata` to check the claims of an SD-JWT VC against its type metadata: extra claims, missing or undisclosed mandatory claims, and `sd` violations. `verify` and `safeVerify` add the result as `typeMetadataVerification` when `loadTypeMetadataFormat` is enabled.

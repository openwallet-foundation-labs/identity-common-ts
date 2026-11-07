---
'@sd-jwt/sd-jwt-vc': patch
---

`SdJwtVcInstance.getVct`, and `verifyTypeMetadata` without type metadata, verify the signature of the SD-JWT VC before they fetch its `vct` (RFC 9901 Section 7.1). Before, they fetched the `vct` and its `extends` chain from an SD-JWT VC with any signature, which let anyone make the verifier send requests to a URL of their choice. Both now need the `verifier`, and take the verification options as a new last parameter. Claims such as `exp` are still not checked.

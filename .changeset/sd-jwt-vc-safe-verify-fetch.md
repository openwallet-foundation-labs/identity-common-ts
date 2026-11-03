---
'@sd-jwt/sd-jwt-vc': patch
---

`SDJwtVcInstance.safeVerify` fetches the status list and the type metadata only when the SD-JWT VC was verified. It used to fetch the `status_list.uri` and `vct` of a credential with an invalid signature too, which let anyone make the verifier send requests to a URL of their choice. Such a credential is no longer reported with `STATUS_*` or `VCT_*` errors, only with the errors of its verification.

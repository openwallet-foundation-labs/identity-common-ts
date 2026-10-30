---
'@sd-jwt/sd-jwt-vc': patch
---

Sub-claims of a protected claim can no longer be selectively disclosed, as SD-JWT VC requires. `issue` rejects a disclosure frame for any sub-claim of `iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity` or `status` (for example the `status_list` of `status`), and verification rejects an SD-JWT VC whose issuer-signed protected claims have a selectively disclosable sub-claim, whether the holder reveals it or not.

---
'@owf/cose': patch
---

`CwtPayload.verifyClaims` rejects a token that does not carry a claim passed as `expectedIssuer`, `expectedSubject` or `expectedAudience`, where it used to skip the check.

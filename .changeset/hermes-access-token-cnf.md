---
'@openid4vc/oauth2': patch
---

Fix the `cnf` claim of a DPoP-bound access token created by `createAccessTokenJwt` on Hermes (React Native). Hermes compilers before 250829098.0.12 (facebook/hermes#2010) return the last property value instead of the object when an object literal in a ternary branch contains an `await`, so the token had `cnf` set to the thumbprint string instead of `{ jkt: <thumbprint> }`.

---
'@sd-jwt/sd-jwt-vc': patch
---

Resolving type metadata now fails when a fetched document describes a different `vct` than the one it was fetched for, for the credential's `vct` and for every `extends` value. The `vctValues` of a resolved chain are read from the documents, so before this change whoever hosted a credential's `vct` URL could serve a document claiming any other type, such as `urn:eudi:pid:1`, and the credential matched requests for that type.

A circular `extends` chain that leads back to the credential's own `vct` is now detected when it is reached, instead of one fetch later.

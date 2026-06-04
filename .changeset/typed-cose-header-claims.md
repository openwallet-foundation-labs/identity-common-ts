---
"@owf/cose": minor
---

Type the known COSE header claims. `kid` (label 4) is now validated as a bstr when decoding protected and unprotected headers, so a malformed `{ 4: undefined }` is rejected for every `Sign1`-derived structure (e.g. a `deviceSignature`) instead of being silently accepted. The other registered labels are enumerated as known keys; additional/private-use labels still pass through. `ProtectedHeaders`/`UnprotectedHeaders` now back their structure with a `TypedMap`, and the `.headers` accessor keeps `kid` typed as a bstr while allowing access to any other integer label.

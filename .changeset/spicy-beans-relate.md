---
"@owf/eudi-lote": patch
---

Simplifies the errors returned by `validateLoTEProfile` by pre-matching the given LoTE to the corresponding profiles' type identifiers:

- When no type matches, the error clearly states that the LoTE Type doesn't match any of the given profiles.
- When one type matches, but fails along the verification, only the errors of this profile are returned for clarity.

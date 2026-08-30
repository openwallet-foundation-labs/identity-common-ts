---
"@owf/token-status-list": patch
---

Keep the `lst` claim of a status list compressed in `StatusListCbor`, so a decoded status list re-encodes to the bytes it was decoded from. DEFLATE has no canonical form, so inflating and deflating again is not guaranteed to reproduce the issuer's stream.

This also fixes two related bugs in the same structure:

- `aggregation_uri` was effectively required, so a status list that omits the claim could not be decoded at all.
- `aggregation_uri` was written with an explicit `undefined` value when no aggregation uri was set, instead of the key being omitted. Status lists encoding the claim that way (including ones this library issued up to 0.3.1) are now rejected on decode.

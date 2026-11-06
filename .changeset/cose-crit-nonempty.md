---
"@owf/cose": patch
---

Reject a COSE `crit` header parameter that is an empty array. RFC 9052 Section 3.1 requires the array to have at least one value.

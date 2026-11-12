---
'@sd-jwt/sd-jwt-vc': patch
---

`aka_vcts` is now a protected claim, as SD-JWT VC draft 23, Section 2.2.2.3 requires. `issue` rejects a disclosure frame for `aka_vcts` or one of its elements, and verification rejects an SD-JWT VC in which `aka_vcts` arrived in a Disclosure or has selectively disclosable elements.

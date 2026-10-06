---
"@owf/eudi-wrprc": patch
---

Accept national schemes (two letters and `:`, e.g. `HR:DE-...`) as semantic identifier initial characters in `sub`, as allowed by ETSI EN 319 412-1 LEG-5.1.4-03 (7) and NAT-5.1.3-03 (7). They produce the existing unknown-prefix warning instead of an error.
